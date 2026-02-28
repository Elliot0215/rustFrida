//! Java hook callback and registry + replacedMethods mapping
//!
//! Contains: JavaHookData, JAVA_HOOK_REGISTRY, CURRENT_HOOK_* globals,
//! helper functions, dispatch_call!, js_call_original, java_hook_callback,
//! replacedMethods mapping (set/get/delete).

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    ensure_registry_initialized, invoke_hook_callback_common,
    BiMap,
};
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::jni_core::*;

// ============================================================================
// Hook registry
// ============================================================================

/// Hook 类型：统一 Clone+Replace 策略
/// 所有回调统一 JNI 调用约定: x0=JNIEnv*, x1=this/jclass, x2+=args
pub(super) enum HookType {
    /// Unified replacement hook
    /// - replacement_addr: heap-allocated replacement ArtMethod (native, jniCode=thunk)
    /// - per_method_hook_target: Some(quickCode) for compiled methods (Layer 3 router hook),
    ///   None for shared stub methods (routed via Layer 1/2)
    Replaced {
        replacement_addr: usize,
        per_method_hook_target: Option<u64>,
    },
}

pub(super) struct JavaHookData {
    pub(super) art_method: u64,
    // Frida-style original method state（unhook 时恢复全部字段）
    pub(super) original_access_flags: u32,
    pub(super) original_entry_point: u64,  // quickCode / entry_point_
    pub(super) original_data: u64,         // data_ / jniCode
    // Hook 路径类型
    pub(super) hook_type: HookType,
    // Backup clone for callOriginal (heap, 原始状态副本)
    pub(super) clone_addr: u64,
    // JNI global ref to jclass (for JNI CallNonvirtual/Static calls)
    pub(super) class_global_ref: usize,
    // Return type char from JNI signature: b'V', b'I', b'J', b'Z', b'L', etc.
    pub(super) return_type: u8,
    // JS callback info
    pub(super) ctx: usize,
    pub(super) callback_bytes: [u8; 16],
    pub(super) method_key: String, // "class.method.sig" for lookup
    pub(super) is_static: bool,
    pub(super) param_count: usize,
    // Per-parameter JNI type descriptors (e.g. ["I", "Ljava/lang/String;", "[B"])
    pub(super) param_types: Vec<String>,
    // Hooked class name (dot notation, for wrapping object args)
    pub(super) class_name: String,
}

unsafe impl Send for JavaHookData {}
unsafe impl Sync for JavaHookData {}

/// Global Java hook registry keyed by art_method address
pub(super) static JAVA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, JavaHookData>>> = Mutex::new(None);

// Callback state globals — set before JS_Call in java_hook_callback, read by js_call_original.
// Protected by JS_ENGINE lock (single-threaded JS execution). Use atomics to avoid UB from
// static mut in multi-threaded context.
pub(super) static CURRENT_HOOK_CTX_PTR: AtomicUsize = AtomicUsize::new(0);
pub(super) static CURRENT_HOOK_ART_METHOD: AtomicU64 = AtomicU64::new(0);

/// Parse JNI signature to extract the return type character.
/// "(II)V" → b'V', "(Ljava/lang/String;)Ljava/lang/Object;" → b'L'
pub(super) fn get_return_type_from_sig(sig: &str) -> u8 {
    if let Some(pos) = sig.rfind(')') {
        let ret = &sig[pos + 1..];
        match ret.as_bytes().first() {
            Some(&c) => c,
            None => b'V',
        }
    } else {
        b'V'
    }
}

pub(super) fn init_java_registry() {
    ensure_registry_initialized(&JAVA_HOOK_REGISTRY);
}

/// Build a unique key string for method lookup
pub(super) fn method_key(class: &str, method: &str, sig: &str) -> String {
    format!("{}.{}{}", class, method, sig)
}

/// Count the number of parameters in a JNI method signature.
/// "(II)V" → 2, "(Ljava/lang/String;I)V" → 2, "()V" → 0
pub(super) fn count_jni_params(sig: &str) -> usize {
    let bytes = sig.as_bytes();
    let mut count = 0;
    let mut i = 0;
    // skip to '('
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    i += 1; // skip '('
    while i < bytes.len() && bytes[i] != b')' {
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1; // skip ';'
            }
            b'[' => {
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    i += 1; // primitive element
                }
            }
            _ => i += 1, // primitive
        }
        count += 1;
    }
    count
}

/// Parse a JNI method signature into individual parameter type descriptors.
/// "(ILjava/lang/String;[B)V" → ["I", "Ljava/lang/String;", "[B"]
pub(super) fn parse_jni_param_types(sig: &str) -> Vec<String> {
    let bytes = sig.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    // skip to '('
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    i += 1; // skip '('
    while i < bytes.len() && bytes[i] != b')' {
        let start = i;
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1; // skip ';'
            }
            b'[' => {
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    i += 1; // primitive element
                }
            }
            _ => i += 1, // primitive
        }
        result.push(String::from_utf8_lossy(&bytes[start..i]).to_string());
    }
    result
}

// ============================================================================
// callOriginal() — JS CFunction invoked from user's hook callback
// ============================================================================

/// Dispatch a JNI call via either static or nonvirtual variant, based on `$is_static`.
/// Consolidates the static/instance arms into one match expression.
macro_rules! dispatch_call {
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr, $ret_ty:ty) => {{
        if $is_static {
            type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty;
            let f: F = jni_fn!($env, F, $static_idx);
            f($env, $cls, $mid, $args)
        } else {
            type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty;
            let f: F = jni_fn!($env, F, $nonvirt_idx);
            f($env, $this, $cls, $mid, $args)
        }
    }};
}

/// Dispatch + check exception + convert result to JSValue.
/// 将 dispatch_call、jni_check_exc 和 JSValue 转换统一为单个宏调用。
macro_rules! dispatch_and_convert {
    // 非 void 原始类型: dispatch → check exc → convert to JSValue
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr,
     $ret_ty:ty, $convert:expr) => {{
        let ret: $ret_ty = dispatch_call!($env, $static_idx, $nonvirt_idx,
                                          $cls, $this, $mid, $args, $is_static, $ret_ty);
        jni_check_exc($env);
        $convert(ret)
    }};
}

/// JS CFunction: ctx.callOriginal()
/// Invokes the cloned ArtMethod via JNI CallNonvirtual*MethodA / CallStatic*MethodA.
/// Returns the method's return value as a JS value.
///
/// Must be called from within a java_hook_callback (reads CURRENT_HOOK_* globals).
unsafe extern "C" fn js_call_original(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let art_method_addr = CURRENT_HOOK_ART_METHOD.load(Ordering::Relaxed);
    let ctx_ptr = CURRENT_HOOK_CTX_PTR.load(Ordering::Relaxed) as *mut hook_ffi::HookContext;
    if ctx_ptr.is_null() || art_method_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // Look up hook data for clone info
    let (clone_addr, class_global_ref, return_type, param_count, is_static) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"callOriginal: hook registry not initialized\0".as_ptr() as *const _,
                );
            }
        };
        let data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"callOriginal: hook data not found\0".as_ptr() as *const _,
                );
            }
        };
        (data.clone_addr, data.class_global_ref, data.return_type, data.param_count, data.is_static)
    }; // lock released

    if clone_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal: no ArtMethod clone available\0".as_ptr() as *const _,
        );
    }

    let hook_ctx = &*ctx_ptr;

    // Unified JNI calling convention: x0=JNIEnv*, x1=this/class, x2+=args
    let env: JniEnv = {
        let e = hook_ctx.x[0] as JniEnv;
        if e.is_null() {
            return ffi::JS_ThrowInternalError(
                ctx,
                b"callOriginal: JNIEnv* is null\0".as_ptr() as *const _,
            );
        }
        e
    };

    // Build jvalue args from HookContext registers (JNI convention: x2-x7 = args[0-5])
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    for i in 0..param_count {
        let val = if i < 6 {
            hook_ctx.x[2 + i]
        } else {
            let sp = hook_ctx.sp as usize;
            *((sp + (i - 6) * 8) as *const u64)
        };
        jargs.push(val);
    }
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };

    // Use clone_addr as jmethodID — it's heap-allocated with 8-byte alignment (bit 0 = 0),
    // so ART treats it as a raw ArtMethod* pointer (not encoded).
    let clone_mid = clone_addr as *mut std::ffi::c_void;
    let cls = class_global_ref as *mut std::ffi::c_void;
    let this_obj = hook_ctx.x[1] as *mut std::ffi::c_void;

    // Clear any pending exception before calling original
    jni_check_exc(env);

    match return_type {
        b'V' => {
            dispatch_call!(env, JNI_CALL_STATIC_VOID_METHOD_A, JNI_CALL_NONVIRTUAL_VOID_METHOD_A,
                           cls, this_obj, clone_mid, jargs_ptr, is_static, ());
            if jni_check_exc(env) {
                if is_static {
                    output_message("[callOriginal] JNI exception in static void call");
                } else {
                    output_message("[callOriginal] JNI exception in nonvirtual void call");
                }
            }
            ffi::qjs_undefined()
        }
        b'Z' => dispatch_and_convert!(env, JNI_CALL_STATIC_BOOLEAN_METHOD_A, JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A,
                    cls, this_obj, clone_mid, jargs_ptr, is_static, u8, |ret: u8| JSValue::bool(ret != 0).raw()),
        b'I' | b'B' | b'C' | b'S' => dispatch_and_convert!(env, JNI_CALL_STATIC_INT_METHOD_A, JNI_CALL_NONVIRTUAL_INT_METHOD_A,
                    cls, this_obj, clone_mid, jargs_ptr, is_static, i32, |ret: i32| JSValue::int(ret).raw()),
        b'J' => dispatch_and_convert!(env, JNI_CALL_STATIC_LONG_METHOD_A, JNI_CALL_NONVIRTUAL_LONG_METHOD_A,
                    cls, this_obj, clone_mid, jargs_ptr, is_static, i64, |ret: i64| ffi::JS_NewBigUint64(ctx, ret as u64)),
        b'F' => dispatch_and_convert!(env, JNI_CALL_STATIC_FLOAT_METHOD_A, JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A,
                    cls, this_obj, clone_mid, jargs_ptr, is_static, f32, |ret: f32| JSValue::float(ret as f64).raw()),
        b'D' => dispatch_and_convert!(env, JNI_CALL_STATIC_DOUBLE_METHOD_A, JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A,
                    cls, this_obj, clone_mid, jargs_ptr, is_static, f64, |ret: f64| JSValue::float(ret).raw()),
        b'L' | b'[' => {
            let ret: *mut std::ffi::c_void = dispatch_call!(env, JNI_CALL_STATIC_OBJECT_METHOD_A, JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A,
                                                            cls, this_obj, clone_mid, jargs_ptr, is_static, *mut std::ffi::c_void);
            jni_check_exc(env);
            if ret.is_null() {
                ffi::qjs_null()
            } else {
                let js_val = ffi::JS_NewBigUint64(ctx, ret as u64);
                // 释放 JNI local ref，避免 local ref table 泄漏
                let delete_local_ref: DeleteLocalRefFn =
                    jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
                delete_local_ref(env, ret);
                js_val
            }
        }
        _ => ffi::qjs_undefined(),
    }
}

// ============================================================================
// Argument marshalling — convert raw JNI register values to JS values
// ============================================================================

/// Convert a raw JNI argument (from register) to a JS value based on its JNI type descriptor.
///
/// Primitive types become JS numbers/booleans/bigints.
/// String objects become JS strings (read via GetStringUTFChars).
/// Other objects become wrapped `{__jptr, __jclass}` for Proxy-based field access.
/// Falls back to BigUint64 if type info is unavailable.
unsafe fn marshal_jni_arg_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => return ffi::JS_NewBigUint64(ctx, raw),
    };

    match sig.as_bytes()[0] {
        b'Z' => JSValue::bool(raw != 0).raw(),
        b'B' => JSValue::int(raw as i8 as i32).raw(),
        b'C' => {
            // char → JS string (single UTF-16 character)
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            JSValue::string(ctx, &s).raw()
        }
        b'S' => JSValue::int(raw as i16 as i32).raw(),
        b'I' => JSValue::int(raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, raw),
        b'F' => {
            // KNOWN LIMITATION: ARM64 ABI passes floats in d0-d7 (FP registers), not x registers.
            // HookContext currently only saves x0-x30. The `raw` value comes from an x register,
            // which may not contain the float argument. This will produce incorrect values.
            // TODO: Extend HookContext to save d0-d7 and read float args from FP registers.
            let f = f32::from_bits(raw as u32);
            JSValue::float(f as f64).raw()
        }
        b'D' => {
            // KNOWN LIMITATION: Same as F — double args are in d registers, not x registers.
            // TODO: Extend HookContext to save d0-d7 and read double args from FP registers.
            let d = f64::from_bits(raw);
            JSValue::float(d).raw()
        }
        b'L' | b'[' => {
            // Object or array — raw is a jobject local ref
            let obj = raw as *mut std::ffi::c_void;
            if obj.is_null() {
                return ffi::qjs_null();
            }

            // String → read as JS string
            if sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn =
                    jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn =
                    jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

                let chars = get_str(env, obj, std::ptr::null_mut());
                if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars)
                        .to_string_lossy()
                        .to_string();
                    rel_str(env, obj, chars);
                    return JSValue::string(ctx, &s).raw();
                }
                // GetStringUTFChars failed — fall through to wrapped object
                jni_check_exc(env);
            }

            // Other object → wrap as {__jptr, __jclass} for Proxy field access
            let wrapper = ffi::JS_NewObject(ctx);
            let wrapper_val = JSValue(wrapper);

            let ptr_val = ffi::JS_NewBigUint64(ctx, raw);
            wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));

            // Extract class name from signature: "Ljava/lang/Foo;" → "java.lang.Foo"
            let type_name = if sig.starts_with('L') && sig.ends_with(';') {
                sig[1..sig.len() - 1].replace('/', ".")
            } else {
                // Array or unknown — use raw signature
                sig.replace('/', ".")
            };
            let cls_val = JSValue::string(ctx, &type_name);
            wrapper_val.set_property(ctx, "__jclass", cls_val);

            wrapper
        }
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

// ============================================================================
// Hook callback (runs in hooked thread, called by ART JNI trampoline)
// ============================================================================

/// Callback invoked by the native hook trampoline when a hooked Java method is called.
/// After "replace with native", ART's JNI trampoline calls our thunk which calls this.
///
/// HookContext contains JNI calling convention registers:
///   x0 = JNIEnv*, x1 = jobject this (instance) or jclass (static), x2-x7 = Java args
///
/// user_data = ArtMethod* address (used for registry lookup).
pub(super) unsafe extern "C" fn java_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    // user_data is ArtMethod* address (used as registry key)
    let art_method_addr = user_data as u64;

    // Copy callback data then release lock before QuickJS operations
    let (ctx_usize, callback_bytes, is_static, param_count, return_type, param_types) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => return,
        };
        (hook_data.ctx, hook_data.callback_bytes, hook_data.is_static,
         hook_data.param_count, hook_data.return_type,
         hook_data.param_types.clone())
    }; // lock released

    // Set callback state globals for js_call_original
    CURRENT_HOOK_CTX_PTR.store(ctx_ptr as usize, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(art_method_addr, Ordering::Relaxed);

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook",
        art_method_addr,
        // 构建 JS 上下文对象：thisObj, args[], env, callOriginal()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let env: JniEnv = hook_ctx.x[0] as JniEnv;

            // thisObj for instance methods (x1 = jobject this)
            if !is_static {
                let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[1]);
                JSValue(js_ctx).set_property(ctx, "thisObj", JSValue(val));
            }

            // args[] — x2-x7 = first 6 args, stack for args 6+
            {
                let arr = ffi::JS_NewArray(ctx);
                for i in 0..param_count {
                    let raw = if i < 6 {
                        hook_ctx.x[2 + i]
                    } else {
                        let sp = hook_ctx.sp as usize;
                        *((sp + (i - 6) * 8) as *const u64)
                    };
                    let val = marshal_jni_arg_to_js(ctx, env, raw, param_types.get(i).map(|s| s.as_str()));
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                JSValue(js_ctx).set_property(ctx, "args", JSValue(arr));
            }

            // env (JNIEnv* — from x0)
            {
                let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[0]);
                JSValue(js_ctx).set_property(ctx, "env", JSValue(val));
            }

            // callOriginal()
            {
                let cname = CString::new("callOriginal").unwrap();
                let func_val = ffi::qjs_new_cfunction(ctx, Some(js_call_original), cname.as_ptr(), 0);
                JSValue(js_ctx).set_property(ctx, "callOriginal", JSValue(func_val));
            }

            js_ctx
        },
        // 处理返回值：根据 return_type 将 JS 返回值写入 HookContext.x[0]
        |ctx, _js_ctx, result| {
            if return_type != b'V' {
                let result_val = JSValue(result);
                let ret_u64 = match return_type {
                    b'F' => {
                        if let Some(f) = result_val.to_float() {
                            (f as f32).to_bits() as u64
                        } else {
                            0u64
                        }
                    }
                    b'D' => {
                        if let Some(f) = result_val.to_float() {
                            f.to_bits()
                        } else {
                            0u64
                        }
                    }
                    _ => {
                        if let Some(v) = result_val.to_u64(ctx) {
                            v
                        } else if let Some(v) = result_val.to_i64(ctx) {
                            v as u64
                        } else {
                            0u64
                        }
                    }
                };
                (*ctx_ptr).x[0] = ret_u64;
            }
        },
    );

    // Clear callback state globals
    CURRENT_HOOK_CTX_PTR.store(0, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(0, Ordering::Relaxed);
}

// ============================================================================
// replacedMethods — 双向映射 original↔replacement ArtMethod
// ============================================================================
//
// 用于 artController 全局 DoCall hook 回调中查找 replacement。
// artController hooks ART 的 DoCall 函数（解释器路径），在 on_enter 回调中
// 通过此映射将 x0 (ArtMethod*) 从 original 替换为 replacement。
// 所有被 hook 方法均通过 per-method deoptimize 强制走解释器 → DoCall 路径。

/// 双向映射 original ArtMethod ↔ replacement ArtMethod
static REPLACED_METHODS: BiMap = BiMap::new();

/// 注册 original → replacement 映射（双向 + C 侧内联查表）
pub(super) fn set_replacement_method(original: u64, replacement: u64) {
    REPLACED_METHODS.init();
    REPLACED_METHODS.insert(original, replacement);
    // 同步到 C 侧内联查表 (thunk 直接扫描，无需 Mutex+HashMap)
    unsafe {
        hook_ffi::hook_art_router_table_add(original, replacement);
    }
}

/// 查找 original 对应的 replacement（如果已注册）
pub(super) fn get_replacement_method(original: u64) -> Option<u64> {
    REPLACED_METHODS.get_forward(original)
}

/// 删除 original → replacement 映射（双向 + C 侧内联查表）
pub(super) fn delete_replacement_method(original: u64) {
    REPLACED_METHODS.remove_by_forward(original);
    // 同步到 C 侧内联查表
    unsafe {
        hook_ffi::hook_art_router_table_remove(original);
    }
}

/// 检查给定地址是否为 replacement ArtMethod
#[allow(dead_code)]
pub(super) fn is_replacement_method(method: u64) -> bool {
    REPLACED_METHODS.contains_reverse(method)
}

// NOTE: art_router_fn has been removed — routing is now done via inline
// g_art_router_table scan in the C-side thunk (no function call needed).


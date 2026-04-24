//! Java.luaFastMethod() backend used by Lua high-frequency callbacks.
//!
//! This is intentionally fast-only: registration rejects methods that do not
//! currently have an independent quick-code entrypoint. Slow/reflection/JNI
//! calls stay in the JS callback path.

use crate::ffi;
use crate::jsapi::callback_util::{
    extract_string_arg, js_u64_to_js_number_or_bigint, set_js_u64_property, throw_internal_error,
    throw_type_error,
};
use crate::value::JSValue;
use std::sync::{Mutex, OnceLock};

use super::art_method::*;
use super::callback::{get_return_type_from_sig, is_floating_point_type, parse_jni_param_types};
use super::jni_core::*;

#[derive(Clone)]
pub(crate) struct LuaFastMethod {
    pub(crate) art_method: u64,
    pub(crate) entry_point: u64,
    entry_point_offset: usize,
    pub(crate) is_static: bool,
    pub(crate) return_type: u8,
    pub(crate) param_types: Vec<String>,
}

static LUA_FAST_METHODS: OnceLock<Mutex<Vec<LuaFastMethod>>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
enum RequestedCompileKind {
    Auto,
    Fast,
    Baseline,
    Optimized,
}

impl RequestedCompileKind {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "fast" => Some(Self::Fast),
            "baseline" => Some(Self::Baseline),
            "optimized" | "opt" => Some(Self::Optimized),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fast => "fast",
            Self::Baseline => "baseline",
            Self::Optimized => "optimized",
        }
    }

    fn sequence(self) -> &'static [u32] {
        match self {
            // Mirrors ART's JitAtFirstUse behavior: fast first, then baseline.
            Self::Auto => &[1, 2, 3],
            Self::Fast => &[1],
            Self::Baseline => &[2],
            Self::Optimized => &[3],
        }
    }
}

struct CompileResult {
    before: u64,
    after: u64,
    success: bool,
    compiled: bool,
    kind: &'static str,
    message: String,
}

fn lua_fast_methods() -> &'static Mutex<Vec<LuaFastMethod>> {
    LUA_FAST_METHODS.get_or_init(|| Mutex::new(Vec::new()))
}

pub(crate) fn get_lua_fast_method(handle: u64) -> Option<LuaFastMethod> {
    if handle == 0 {
        return None;
    }
    let methods = lua_fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.get((handle - 1) as usize).cloned()
}

unsafe fn parse_lua_fast_options(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<(bool, RequestedCompileKind), ffi::JSValue> {
    if argc < 4 {
        return Ok((false, RequestedCompileKind::Auto));
    }
    let opt = JSValue(*argv.add(3));
    if opt.is_bool() {
        return Ok((opt.to_bool().unwrap_or(false), RequestedCompileKind::Auto));
    }
    if opt.is_string() {
        let Some(kind_s) = opt.to_string(ctx) else {
            return Ok((false, RequestedCompileKind::Auto));
        };
        let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
            return Err(throw_type_error(ctx, b"invalid compile kind\0"));
        };
        return Ok((true, kind));
    }
    if opt.is_object() {
        let compile_val = opt.get_property(ctx, "compile");
        let should_compile = compile_val.to_bool().unwrap_or(false);
        compile_val.free(ctx);

        let kind_val = opt.get_property(ctx, "kind");
        let kind = if kind_val.is_string() {
            let kind_s = kind_val.to_string(ctx).unwrap_or_else(|| "auto".to_string());
            let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
                kind_val.free(ctx);
                return Err(throw_type_error(ctx, b"invalid compile kind\0"));
            };
            kind
        } else {
            RequestedCompileKind::Auto
        };
        kind_val.free(ctx);
        return Ok((should_compile, kind));
    }
    Ok((false, RequestedCompileKind::Auto))
}

pub(crate) unsafe extern "C" fn js_java_lua_fast_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(ctx, b"luaFastMethod(class, method, sig[, options]) requires at least 3 arguments\0");
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let (art_method, is_static) =
        match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
            Ok(v) => v,
            Err(msg) => return throw_internal_error(ctx, msg),
        };

    let (should_compile, compile_kind) = match parse_lua_fast_options(ctx, argc, argv) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let mut entry_point = read_entry_point(art_method, spec.entry_point_offset);
    if is_art_quick_entrypoint(entry_point, &bridge) && should_compile {
        let compile = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, compile_kind);
        entry_point = compile.after;
        crate::jsapi::console::output_verbose(&format!(
            "[luaFastMethod] compile {}.{}{} kind={} success={} before={:#x} after={:#x} msg={}",
            class_name,
            method_name,
            actual_sig,
            compile.kind,
            compile.success,
            compile.before,
            compile.after,
            compile.message
        ));
    }
    if is_art_quick_entrypoint(entry_point, &bridge) {
        return throw_internal_error(
            ctx,
            format!(
                "luaFastMethod rejected {}.{}{}: no independent quick entrypoint (entry={:#x})",
                class_name, method_name, actual_sig, entry_point
            ),
        );
    }

    let method = LuaFastMethod {
        art_method,
        entry_point,
        entry_point_offset: spec.entry_point_offset,
        is_static,
        return_type: get_return_type_from_sig(&actual_sig),
        param_types: parse_jni_param_types(&actual_sig),
    };
    let mut methods = lua_fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.push(method);
    js_u64_to_js_number_or_bigint(ctx, methods.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_compile_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(ctx, b"compileMethod(class, method, sig[, kind]) requires at least 3 arguments\0");
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };
    let kind = if argc >= 4 {
        if let Some(s) = JSValue(*argv.add(3)).to_string(ctx) {
            match RequestedCompileKind::from_str(s.as_str()) {
                Some(k) => k,
                None => return throw_type_error(ctx, b"invalid compile kind\0"),
            }
        } else {
            RequestedCompileKind::Auto
        }
    } else {
        RequestedCompileKind::Auto
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let (art_method, _is_static) =
        match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
            Ok(v) => v,
            Err(msg) => return throw_internal_error(ctx, msg),
        };
    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let result = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, kind);

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    obj_v.set_property(ctx, "success", JSValue::bool(result.success));
    obj_v.set_property(ctx, "compiled", JSValue::bool(result.compiled));
    obj_v.set_property(ctx, "kind", JSValue::string(ctx, result.kind));
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &result.message));
    set_js_u64_property(ctx, obj, "artMethod", art_method);
    set_js_u64_property(ctx, obj, "before", result.before);
    set_js_u64_property(ctx, obj, "after", result.after);
    obj
}

pub(crate) unsafe extern "C" fn js_java_jit_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let _env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let Some(info) = probe_jit_runtime_info() else {
        return throw_internal_error(ctx, "JIT runtime info unavailable".to_string());
    };

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    set_js_u64_property(ctx, obj, "runtime", info.runtime);
    set_js_u64_property(ctx, obj, "javaVmOffset", info.java_vm_offset as u64);
    set_js_u64_property(ctx, obj, "jitOffset", info.jit_offset as u64);
    set_js_u64_property(ctx, obj, "jitCodeCacheOffset", info.jit_code_cache_offset as u64);
    set_js_u64_property(ctx, obj, "directJit", info.direct_jit);
    set_js_u64_property(ctx, obj, "runtimeJitCodeCache", info.runtime_jit_code_cache);
    set_js_u64_property(ctx, obj, "directGetCodeCache", info.direct_get_code_cache);
    set_js_u64_property(ctx, obj, "foundJit", info.found_jit);
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &info.message));
    obj
}

unsafe fn compile_art_method_to_quick(
    env: JniEnv,
    art_method: u64,
    entry_point_offset: usize,
    bridge: &ArtBridgeFunctions,
    kind: RequestedCompileKind,
) -> CompileResult {
    let before = read_entry_point(art_method, entry_point_offset);
    if !is_art_quick_entrypoint(before, bridge) {
        return CompileResult {
            before,
            after: before,
            success: true,
            compiled: false,
            kind: "already-quick",
            message: "method already has independent quick code".to_string(),
        };
    }

    let Some(jit) = find_jit_instance() else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit* not found".to_string(),
        };
    };
    let Some(thread) = current_art_thread(env) else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Thread::Current() unavailable".to_string(),
        };
    };
    let compile_sym = crate::jsapi::module::libart_dlsym(
        "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadENS_15CompilationKindEb",
    );
    if compile_sym.is_null() {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit::CompileMethod symbol not found".to_string(),
        };
    }

    type CompileMethodFn = unsafe extern "C" fn(
        this: u64,
        method: u64,
        thread: u64,
        compilation_kind: u32,
        prejit: u8,
    ) -> u8;
    let compile_method: CompileMethodFn = std::mem::transmute(compile_sym);

    let mut last_kind = kind.label();
    let mut saw_compile_success = false;
    for k in kind.sequence() {
        last_kind = match *k {
            1 => "fast",
            2 => "baseline",
            3 => "optimized",
            _ => "unknown",
        };
        let ok = compile_method(jit, art_method, thread, *k, 0) != 0;
        let after = read_entry_point(art_method, entry_point_offset);
        if ok {
            saw_compile_success = true;
        }
        if !is_art_quick_entrypoint(after, bridge) {
            return CompileResult {
                before,
                after,
                success: true,
                compiled: true,
                kind: last_kind,
                message: format!("Jit::CompileMethod({}) succeeded", last_kind),
            };
        }
    }

    let after = read_entry_point(art_method, entry_point_offset);
    CompileResult {
        before,
        after,
        success: false,
        compiled: saw_compile_success,
        kind: last_kind,
        message: if saw_compile_success {
            "JIT reported success but entrypoint is still a shared ART bridge".to_string()
        } else {
            "Jit::CompileMethod returned false".to_string()
        },
    }
}

unsafe fn current_art_thread(env: JniEnv) -> Option<u64> {
    let sym = crate::jsapi::module::libart_dlsym("_ZN3art6Thread7CurrentEv");
    if !sym.is_null() {
        type ThreadCurrentFn = unsafe extern "C" fn() -> u64;
        let thread_current: ThreadCurrentFn = std::mem::transmute(sym);
        let thread = thread_current() & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    if !env.is_null() {
        let thread = *((env as usize + 8) as *const u64) & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    None
}

extern "C" {
    fn art_quick_call_shim(
        fn_ptr: *const std::ffi::c_void,
        thread: *mut std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> u64;
    #[link_name = "art_quick_call_shim"]
    fn art_quick_call_shim_f64(
        fn_ptr: *const std::ffi::c_void,
        thread: *mut std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> f64;
    #[link_name = "art_quick_call_shim"]
    fn art_quick_call_shim_f32(
        fn_ptr: *const std::ffi::c_void,
        thread: *mut std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> f32;
}

pub(crate) unsafe fn invoke_lua_fast_method(
    method: &LuaFastMethod,
    receiver: u64,
    args: &[u64],
) -> Result<u64, String> {
    if !method.is_static && receiver == 0 {
        return Err("jcall instance receiver is null".to_string());
    }
    if args.len() != method.param_types.len() {
        return Err(format!(
            "jcall argument count mismatch: expected {}, got {}",
            method.param_types.len(),
            args.len()
        ));
    }

    let mut gpr = [0u64; 8];
    let mut fpr = [0.0f64; 8];
    let mut stk: Vec<u64> = Vec::new();

    gpr[0] = method.art_method;
    let mut gp_index = 1usize;
    let mut fp_index = 0usize;
    if !method.is_static {
        gpr[1] = receiver;
        gp_index = 2;
    }

    for (i, type_sig) in method.param_types.iter().enumerate() {
        let raw = args[i];
        if is_floating_point_type(Some(type_sig.as_str())) {
            if fp_index < 8 {
                fpr[fp_index] = if type_sig == "F" {
                    f64::from_bits((raw as u32) as u64)
                } else {
                    f64::from_bits(raw)
                };
                fp_index += 1;
            } else {
                stk.push(raw);
            }
        } else if gp_index < 8 {
            gpr[gp_index] = raw;
            gp_index += 1;
        } else {
            stk.push(raw);
        }
    }

    let entry_point = read_entry_point(method.art_method, method.entry_point_offset);
    let fn_ptr = if entry_point == 0 { method.entry_point } else { entry_point } as *const std::ffi::c_void;
    let stk_ptr = if stk.is_empty() { std::ptr::null() } else { stk.as_ptr() };
    let Some(ret) = crate::lua::callback::with_current_quick_runnable(|thread| match method.return_type {
        b'V' => {
            art_quick_call_shim(fn_ptr, thread, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk.len());
            0
        }
        b'F' => {
            let r = art_quick_call_shim_f32(fn_ptr, thread, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk.len());
            r.to_bits() as u64
        }
        b'D' => {
            let r = art_quick_call_shim_f64(fn_ptr, thread, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk.len());
            r.to_bits()
        }
        _ => art_quick_call_shim(fn_ptr, thread, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk.len()),
    }) else {
        return Err("jcall is only available inside quick Lua callbacks".to_string());
    };
    Ok(ret)
}

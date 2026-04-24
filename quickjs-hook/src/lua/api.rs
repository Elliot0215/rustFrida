use super::ffi;
use super::state::LuaState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const REF_KIND_NONE: u8 = 0;
const REF_KIND_JNI_LOCAL: u8 = 1;
const REF_KIND_RAW_MIRROR: u8 = 2;
static CALLBACK_LOG_MARK: AtomicU64 = AtomicU64::new(0);

// 当前 callback 线程的 JNIEnv 和引用形态 (JNI local ref / quick raw mirror)。
std::thread_local! {
    static CURRENT_ENV: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CURRENT_REF_KIND: std::cell::Cell<u8> = const { std::cell::Cell::new(REF_KIND_NONE) };
    static FAST_ORIG_REQUESTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static QUICK_ORIG_RESULT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn set_current_env(env: *const std::ffi::c_void) {
    CURRENT_ENV.with(|c| c.set(env as usize));
    CURRENT_REF_KIND.with(|c| c.set(if env.is_null() { REF_KIND_NONE } else { REF_KIND_JNI_LOCAL }));
}

pub(crate) fn set_current_raw_mirror_env(env: *const std::ffi::c_void) {
    CURRENT_ENV.with(|c| c.set(env as usize));
    CURRENT_REF_KIND.with(|c| c.set(if env.is_null() { REF_KIND_NONE } else { REF_KIND_RAW_MIRROR }));
}

pub(crate) fn clear_current_env() {
    CURRENT_ENV.with(|c| c.set(0));
    CURRENT_REF_KIND.with(|c| c.set(REF_KIND_NONE));
}

pub(crate) fn get_current_env() -> *const std::ffi::c_void {
    CURRENT_ENV.with(|c| c.get() as *const std::ffi::c_void)
}

fn get_current_ref_context() -> (*const std::ffi::c_void, u8) {
    let env = CURRENT_ENV.with(|c| c.get() as *const std::ffi::c_void);
    let kind = CURRENT_REF_KIND.with(|c| c.get());
    (env, kind)
}

pub(crate) fn clear_fast_orig_requested() {
    FAST_ORIG_REQUESTED.with(|c| c.set(false));
}

pub(crate) fn mark_fast_orig_requested() {
    FAST_ORIG_REQUESTED.with(|c| c.set(true));
}

pub(crate) fn take_fast_orig_requested() -> bool {
    FAST_ORIG_REQUESTED.with(|c| {
        let v = c.get();
        c.set(false);
        v
    })
}

pub(crate) fn clear_quick_orig_result() {
    QUICK_ORIG_RESULT.with(|c| c.set(None));
}

pub(crate) fn set_quick_orig_result(raw: u64) {
    QUICK_ORIG_RESULT.with(|c| c.set(Some(raw)));
}

pub(crate) fn take_quick_orig_result() -> Option<u64> {
    QUICK_ORIG_RESULT.with(|c| {
        let v = c.get();
        c.set(None);
        v
    })
}

pub(crate) unsafe fn register_lua_apis(state: &LuaState) {
    state.register_fn("print", Some(lua_print));
    state.register_fn("jcall", Some(lua_jcall));
    state.register_fn("jstr", Some(lua_jstr));
    state.register_fn("callback_count", Some(lua_callback_count));
    state.register_fn("callback_log_mark", Some(lua_callback_log_mark));
}

pub(crate) fn reset_callback_log_mark() {
    CALLBACK_LOG_MARK.store(0, Ordering::Release);
}

#[inline]
pub(crate) fn lua_upvalueindex(i: i32) -> i32 {
    ffi::LUA_REGISTRYINDEX - i
}

/// Lua print() → console callback
unsafe extern "C" fn lua_print(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let n = ffi::lua_gettop(L);
    let mut parts = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let tp = ffi::lua_type(L, i);
        if tp == ffi::LUA_TSTRING as i32 {
            let s = ffi::lua_tostring_ex(L, i);
            if !s.is_null() {
                parts.push(std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned());
            } else {
                parts.push("nil".to_string());
            }
        } else if tp == ffi::LUA_TLIGHTUSERDATA as i32 {
            // Keep print() side-effect free in hook callbacks. Users can call
            // jstr(obj) explicitly when they want JNI Object.toString().
            let ptr = ffi::lua_touserdata(L, i) as u64;
            parts.push(format!("0x{:x}", ptr));
        } else {
            match tp as u32 {
                ffi::LUA_TNIL => parts.push("nil".to_string()),
                ffi::LUA_TBOOLEAN => {
                    let b = ffi::lua_toboolean(L, i);
                    parts.push(if b != 0 { "true" } else { "false" }.to_string());
                }
                ffi::LUA_TNUMBER => {
                    if ffi::lua_isinteger(L, i) != 0 {
                        let n = ffi::lua_tointeger_ex(L, i);
                        parts.push(format!("{}", n));
                    } else {
                        let n = ffi::lua_tonumber_ex(L, i);
                        parts.push(format!("{}", n));
                    }
                }
                _ => parts.push(format!("<{}>", lua_typename_str(tp))),
            }
        }
    }
    let msg = parts.join("\t");
    crate::jsapi::console::output_message(&msg);
    0
}

unsafe fn lua_typename_str(tp: i32) -> &'static str {
    match tp as u32 {
        ffi::LUA_TNIL => "nil",
        ffi::LUA_TBOOLEAN => "boolean",
        ffi::LUA_TNUMBER => "number",
        ffi::LUA_TSTRING => "string",
        ffi::LUA_TTABLE => "table",
        ffi::LUA_TFUNCTION => "function",
        ffi::LUA_TUSERDATA => "userdata",
        ffi::LUA_TLIGHTUSERDATA => "lightuserdata",
        ffi::LUA_TTHREAD => "thread",
        _ => "unknown",
    }
}

/// jstr(obj) — 将 Java 对象 (lightuserdata) 转为 Lua string
/// 调用 Object.toString() via JNI
unsafe extern "C" fn lua_jstr(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 1 || ffi::lua_type(L, 1) != ffi::LUA_TLIGHTUSERDATA as i32 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let ptr = ffi::lua_touserdata(L, 1) as u64;
    if ptr == 0 {
        let cs = c"null";
        ffi::lua_pushstring(L, cs.as_ptr());
        return 1;
    }
    let (env, ref_kind) = get_current_ref_context();
    if env.is_null() || ref_kind == REF_KIND_NONE {
        ffi::lua_pushnil(L);
        return 1;
    }
    let result = match local_ref_from_lua_obj(env, ptr, ref_kind) {
        Some((local, delete_local)) => {
            let result = jni_tostring(local as u64, env);
            if delete_local {
                delete_local_ref(env, local);
            }
            result
        }
        None => None,
    };
    match result {
        Some(s) => {
            let cs = std::ffi::CString::new(s).unwrap_or_default();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        None => ffi::lua_pushnil(L),
    }
    1
}

/// jcall(handle, receiver, ...) — direct ART quick-code call from a quick Lua callback.
///
/// Handles are created on the JS cold path with Java.luaFastMethod().
unsafe extern "C" fn lua_jcall(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 1 || ffi::lua_type(L, 1) != ffi::LUA_TNUMBER as i32 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let handle = ffi::lua_tointeger_ex(L, 1) as u64;
    let Some(method) = crate::jsapi::java::java_lua_fast_api::get_lua_fast_method(handle) else {
        ffi::lua_pushnil(L);
        return 1;
    };

    let mut receiver = 0u64;
    let mut first_arg = 2i32;
    if !method.is_static {
        if ffi::lua_gettop(L) < 2 || ffi::lua_type(L, 2) != ffi::LUA_TLIGHTUSERDATA as i32 {
            ffi::lua_pushnil(L);
            return 1;
        }
        receiver = ffi::lua_touserdata(L, 2) as u64;
        first_arg = 3;
    }

    if ffi::lua_gettop(L) < first_arg + method.param_types.len() as i32 - 1 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let mut args = Vec::with_capacity(method.param_types.len());
    for (i, sig) in method.param_types.iter().enumerate() {
        args.push(lua_to_jvalue(
            L,
            first_arg + i as i32,
            Some(sig.as_str()),
            std::ptr::null_mut(),
        ));
    }

    match crate::jsapi::java::java_lua_fast_api::invoke_lua_fast_method(&method, receiver, &args) {
        Ok(raw) => push_return_value(L, raw, method.return_type, std::ptr::null_mut()),
        Err(_) => ffi::lua_pushnil(L),
    }
    1
}

unsafe extern "C" fn lua_callback_count(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let (total, _, _, _, _, _, _, _) = super::callback_stats();
    ffi::lua_pushinteger(L, total as ffi::lua_Integer);
    1
}

unsafe extern "C" fn lua_callback_log_mark(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let step = if ffi::lua_gettop(L) >= 1 && ffi::lua_type(L, 1) == ffi::LUA_TNUMBER as i32 {
        ffi::lua_tointeger_ex(L, 1).max(1) as u64
    } else {
        10000
    };
    let (total, _, _, _, _, _, _, _) = super::callback_stats();
    let mark = (total / step) * step;
    if mark == 0 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let mut prev = CALLBACK_LOG_MARK.load(Ordering::Acquire);
    while mark > prev {
        match CALLBACK_LOG_MARK.compare_exchange(prev, mark, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                ffi::lua_pushinteger(L, mark as ffi::lua_Integer);
                return 1;
            }
            Err(v) => prev = v,
        }
    }
    ffi::lua_pushnil(L);
    1
}

unsafe fn local_ref_from_lua_obj(
    env: *const std::ffi::c_void,
    obj: u64,
    ref_kind: u8,
) -> Option<(*mut std::ffi::c_void, bool)> {
    if obj == 0 || env.is_null() {
        return None;
    }
    match ref_kind {
        REF_KIND_JNI_LOCAL => {
            let local = new_jni_local_ref(env, obj as *mut std::ffi::c_void);
            if local.is_null() {
                None
            } else {
                Some((local, true))
            }
        }
        REF_KIND_RAW_MIRROR => {
            let local = raw_mirror_to_local_ref(env, obj as *mut std::ffi::c_void);
            if local.is_null() {
                None
            } else {
                Some((local, true))
            }
        }
        _ => None,
    }
}

unsafe fn new_jni_local_ref(
    env: *const std::ffi::c_void,
    obj: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    if env.is_null() || obj.is_null() {
        return std::ptr::null_mut();
    }
    let vtable = *(env as *const *const usize);
    type NewLocalRefFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    let new_local_ref: NewLocalRefFn = std::mem::transmute(*vtable.add(25));
    let local = new_local_ref(env, obj);
    if jni_exception_check_and_clear(env) {
        return std::ptr::null_mut();
    }
    local
}

unsafe fn raw_mirror_to_local_ref(
    env: *const std::ffi::c_void,
    raw: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    if env.is_null() || raw.is_null() {
        return std::ptr::null_mut();
    }

    type ArtNewLocalRefFn =
        unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    static ART_NEW_LOCAL_REF: OnceLock<Option<ArtNewLocalRefFn>> = OnceLock::new();

    let local = if let Some(add_ref) = *ART_NEW_LOCAL_REF.get_or_init(|| {
        let sym = crate::jsapi::module::libart_dlsym(
            "_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE",
        );
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute(sym))
        }
    }) {
        add_ref(env as *mut std::ffi::c_void, raw)
    } else {
        std::ptr::null_mut()
    };
    if jni_exception_check_and_clear(env) {
        return std::ptr::null_mut();
    }
    local
}

unsafe fn delete_local_ref(env: *const std::ffi::c_void, obj: *mut std::ffi::c_void) {
    if env.is_null() || obj.is_null() {
        return;
    }
    let vtable = *(env as *const *const usize);
    type DeleteLocalRefFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void);
    let del_local: DeleteLocalRefFn = std::mem::transmute(*vtable.add(23));
    del_local(env, obj);
}

unsafe fn jni_exception_check_and_clear(env: *const std::ffi::c_void) -> bool {
    if env.is_null() {
        return false;
    }
    let vtable = *(env as *const *const usize);
    type ExceptionCheckFn = unsafe extern "C" fn(*const std::ffi::c_void) -> u8;
    type ExceptionClearFn = unsafe extern "C" fn(*const std::ffi::c_void);
    let exc_check: ExceptionCheckFn = std::mem::transmute(*vtable.add(228));
    let exc_clear: ExceptionClearFn = std::mem::transmute(*vtable.add(17));
    if exc_check(env) != 0 {
        exc_clear(env);
        true
    } else {
        false
    }
}

/// 通过 JNI 调用 Object.toString()
unsafe fn jni_tostring(obj: u64, env: *const std::ffi::c_void) -> Option<String> {
    if obj == 0 || env.is_null() {
        return None;
    }
    let vtable = *(env as *const *const usize);

    // IsInstanceOf (vtable index 32)
    type IsInstanceOfFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u8;
    // FindClass (vtable index 6)
    type FindClassFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    // GetStringUTFChars (vtable index 169)
    type GetStringUtfCharsFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut u8) -> *const std::os::raw::c_char;
    // ReleaseStringUTFChars (vtable index 170)
    type ReleaseStringUtfCharsFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *const std::os::raw::c_char);
    // DeleteLocalRef (vtable index 23)
    type DeleteLocalRefFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void);
    // ExceptionCheck (vtable index 228)
    type ExceptionCheckFn = unsafe extern "C" fn(*const std::ffi::c_void) -> u8;
    // ExceptionClear (vtable index 17)
    type ExceptionClearFn = unsafe extern "C" fn(*const std::ffi::c_void);

    let obj_ptr = obj as *mut std::ffi::c_void;

    // 先尝试作为 String 直接读取
    let is_instance: IsInstanceOfFn = std::mem::transmute(*vtable.add(32));
    let find_class: FindClassFn = std::mem::transmute(*vtable.add(6));
    let exc_check: ExceptionCheckFn = std::mem::transmute(*vtable.add(228));
    let exc_clear: ExceptionClearFn = std::mem::transmute(*vtable.add(17));
    let del_local: DeleteLocalRefFn = std::mem::transmute(*vtable.add(23));

    let string_class = find_class(env, c"java/lang/String".as_ptr());
    if string_class.is_null() {
        if exc_check(env) != 0 { exc_clear(env); }
        return try_tostring_via_method(env, vtable, obj_ptr);
    }

    if is_instance(env, obj_ptr, string_class) != 0 {
        del_local(env, string_class);
        let get_str: GetStringUtfCharsFn = std::mem::transmute(*vtable.add(169));
        let rel_str: ReleaseStringUtfCharsFn = std::mem::transmute(*vtable.add(170));
        let chars = get_str(env, obj_ptr, std::ptr::null_mut());
        if chars.is_null() {
            if exc_check(env) != 0 { exc_clear(env); }
            return None;
        }
        let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().into_owned();
        rel_str(env, obj_ptr, chars);
        return Some(s);
    }
    del_local(env, string_class);

    try_tostring_via_method(env, vtable, obj_ptr)
}

unsafe fn try_tostring_via_method(
    env: *const std::ffi::c_void,
    vtable: *const usize,
    obj_ptr: *mut std::ffi::c_void,
) -> Option<String> {
    type GetObjectClassFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    type GetMethodIdFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *const std::os::raw::c_char, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    type CallObjectMethodAFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> *mut std::ffi::c_void;
    type GetStringUtfCharsFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut u8) -> *const std::os::raw::c_char;
    type ReleaseStringUtfCharsFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *const std::os::raw::c_char);
    type DeleteLocalRefFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void);
    type ExceptionCheckFn = unsafe extern "C" fn(*const std::ffi::c_void) -> u8;
    type ExceptionClearFn = unsafe extern "C" fn(*const std::ffi::c_void);

    let get_obj_class: GetObjectClassFn = std::mem::transmute(*vtable.add(31));
    let get_method_id: GetMethodIdFn = std::mem::transmute(*vtable.add(33));
    let call_obj_method: CallObjectMethodAFn = std::mem::transmute(*vtable.add(36));
    let get_str: GetStringUtfCharsFn = std::mem::transmute(*vtable.add(169));
    let rel_str: ReleaseStringUtfCharsFn = std::mem::transmute(*vtable.add(170));
    let del_local: DeleteLocalRefFn = std::mem::transmute(*vtable.add(23));
    let exc_check: ExceptionCheckFn = std::mem::transmute(*vtable.add(228));
    let exc_clear: ExceptionClearFn = std::mem::transmute(*vtable.add(17));

    let cls = get_obj_class(env, obj_ptr);
    if cls.is_null() {
        if exc_check(env) != 0 { exc_clear(env); }
        return None;
    }

    let mid = get_method_id(env, cls, c"toString".as_ptr(), c"()Ljava/lang/String;".as_ptr());
    del_local(env, cls);
    if mid.is_null() {
        if exc_check(env) != 0 { exc_clear(env); }
        return None;
    }

    let str_obj = call_obj_method(env, obj_ptr, mid, std::ptr::null());
    if str_obj.is_null() {
        if exc_check(env) != 0 { exc_clear(env); }
        return None;
    }

    let chars = get_str(env, str_obj, std::ptr::null_mut());
    if chars.is_null() {
        del_local(env, str_obj);
        if exc_check(env) != 0 { exc_clear(env); }
        return None;
    }

    let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().into_owned();
    rel_str(env, str_obj, chars);
    del_local(env, str_obj);
    Some(s)
}

/// self:orig() — 原始参数调用原始方法
/// self:orig(a1, a2, ...) — 自定义参数调用原始方法
/// 注意: `:` 语法会把 self 作为第一个参数传入 (Lua stack index 1)
/// upvalue 1 = lightuserdata (CallbackContext*)
pub(crate) unsafe extern "C" fn lua_call_original(
    L: *mut ffi::lua_State,
) -> std::os::raw::c_int {
    let ctx_ptr = ffi::lua_touserdata(L, lua_upvalueindex(1));
    if ctx_ptr.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cb_ctx = &*(ctx_ptr as *const super::callback::CallbackContext);

    // stack: [self, arg1, arg2, ...]
    // self:orig() → nargs=1 (只有 self), 用原始参数
    // self:orig(a,b) → nargs=3 (self + 2 args), 用自定义参数
    let nargs = ffi::lua_gettop(L);
    let user_arg_count = nargs - 1; // 减去 self

    let (this_obj, jargs_ptr, jargs_buf) = if user_arg_count > 0 && user_arg_count as usize == cb_ctx.param_count {
        // 自定义参数: Lua → JNI jvalue 转换
        let mut jargs: Vec<u64> = Vec::with_capacity(cb_ctx.param_count);
        for i in 0..cb_ctx.param_count {
            let lua_idx = (i + 2) as i32; // stack index 2, 3, ...
            let type_sig = cb_ctx.param_types.get(i).map(|s| s.as_str());
            jargs.push(lua_to_jvalue(L, lua_idx, type_sig, cb_ctx.env));
        }
        (cb_ctx.this_obj, jargs.as_ptr() as *const std::ffi::c_void, Some(jargs))
    } else {
        // 原始参数: 对齐 JS $orig，调用瞬间从 HookContext 寄存器重建，
        // 避免在高频/GC 下使用进入 callback 时缓存的旧引用。
        let hook_ctx = if cb_ctx.hook_ctx_ptr.is_null() {
            std::ptr::null()
        } else {
            cb_ctx.hook_ctx_ptr as *const crate::ffi::hook::HookContext
        };
        if hook_ctx.is_null() {
            (cb_ctx.this_obj, cb_ctx.jargs_ptr, None)
        } else {
            let hook_ctx_ref = unsafe { &*hook_ctx };
            let jargs = crate::jsapi::java::callback::build_jargs_from_registers(
                hook_ctx_ref,
                cb_ctx.param_count,
                &cb_ctx.param_types,
            );
            let this_obj = if cb_ctx.is_static { 0 } else { hook_ctx_ref.x[1] };
            let jargs_ptr = if cb_ctx.param_count > 0 {
                jargs.as_ptr() as *const std::ffi::c_void
            } else {
                std::ptr::null()
            };
            (this_obj, jargs_ptr, Some(jargs))
        }
    };

    if cb_ctx.use_blr && cb_ctx.quick_trampoline != 0 {
        let thread_id = crate::current_thread_id_u64();
        let can_fast_orig = !cb_ctx.hook_ctx_ptr.is_null()
            && crate::jsapi::java::callback::prepare_fast_orig_router_frame(
                cb_ctx.env,
                &*(cb_ctx.hook_ctx_ptr as *const crate::ffi::hook::HookContext),
                cb_ctx.is_static,
                cb_ctx.param_count,
                &cb_ctx.param_types,
            );
        if can_fast_orig
            && unsafe {
                crate::ffi::hook::fast_orig_set(
                    thread_id,
                    cb_ctx.art_method,
                    cb_ctx.quick_trampoline,
                )
            } == 0
        {
            mark_fast_orig_requested();
            ffi::lua_pushnil(L);
            return 1;
        }
    }

    let ret = crate::jsapi::java::callback::invoke_original_jni(
        cb_ctx.env,
        cb_ctx.art_method,
        cb_ctx.class_global_ref,
        this_obj,
        cb_ctx.return_type,
        cb_ctx.is_static,
        jargs_ptr,
        cb_ctx.quick_trampoline,
        cb_ctx.use_blr,
    );

    // 保持 jargs_buf 存活到 invoke 完成
    drop(jargs_buf);

    push_return_value(L, ret, cb_ctx.return_type, cb_ctx.env);
    1
}

/// Lua 值 → JNI jvalue (u64)
pub(crate) unsafe fn lua_to_jvalue(
    L: *mut ffi::lua_State,
    idx: i32,
    type_sig: Option<&str>,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> u64 {
    if ffi::lua_isnil(L, idx) {
        return 0;
    }
    let sig = type_sig.unwrap_or("L");
    match sig.as_bytes()[0] {
        b'Z' => ffi::lua_toboolean(L, idx) as u64,
        b'B' => ffi::lua_tointeger_ex(L, idx) as i8 as u64,
        b'C' => ffi::lua_tointeger_ex(L, idx) as u16 as u64,
        b'S' => ffi::lua_tointeger_ex(L, idx) as i16 as u64,
        b'I' => ffi::lua_tointeger_ex(L, idx) as i32 as u64,
        b'J' => ffi::lua_tointeger_ex(L, idx) as u64,
        b'F' => (ffi::lua_tonumber_ex(L, idx) as f32).to_bits() as u64,
        b'D' => ffi::lua_tonumber_ex(L, idx).to_bits(),
        b'L' | b'[' => {
            let tp = ffi::lua_type(L, idx);
            if tp == ffi::LUA_TLIGHTUSERDATA as i32 {
                ffi::lua_touserdata(L, idx) as u64
            } else if tp == ffi::LUA_TSTRING as i32 && !env.is_null() {
                lua_string_to_jstring(L, idx, env)
            } else if tp == ffi::LUA_TNUMBER as i32 {
                ffi::lua_tointeger_ex(L, idx) as u64
            } else {
                0
            }
        }
        _ => ffi::lua_tointeger_ex(L, idx) as u64,
    }
}

/// Lua string → Java String (NewStringUTF)
pub(crate) unsafe fn lua_string_to_jstring(
    L: *mut ffi::lua_State,
    idx: i32,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> u64 {
    let s = ffi::lua_tostring_ex(L, idx);
    if s.is_null() || env.is_null() {
        return 0;
    }
    let vtable = *(env as *const *const usize);
    type NewStringUtfFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    let new_string: NewStringUtfFn = std::mem::transmute(*vtable.add(167));
    new_string(env as *const std::ffi::c_void, s) as u64
}

unsafe fn push_return_value(
    L: *mut ffi::lua_State,
    raw: u64,
    return_type: u8,
    env: crate::jsapi::java::jni_core::JniEnv,
) {
    match return_type {
        b'V' => ffi::lua_pushnil(L),
        b'Z' => ffi::lua_pushboolean(L, if raw != 0 { 1 } else { 0 }),
        b'B' => ffi::lua_pushinteger(L, raw as i8 as ffi::lua_Integer),
        b'C' => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            let cs = std::ffi::CString::new(s).unwrap();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        b'S' => ffi::lua_pushinteger(L, raw as i16 as ffi::lua_Integer),
        b'I' => ffi::lua_pushinteger(L, raw as i32 as ffi::lua_Integer),
        b'J' => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
        b'F' => ffi::lua_pushnumber(L, f32::from_bits(raw as u32) as ffi::lua_Number),
        b'D' => ffi::lua_pushnumber(L, f64::from_bits(raw) as ffi::lua_Number),
        b'L' | b'[' => {
            if raw == 0 {
                ffi::lua_pushnil(L);
            } else {
                ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
    }
}

/// 将 JNI 参数推入 Lua 栈 (根据类型签名)
/// - String → Lua string (via GetStringUTFChars)
/// - Object (Ljava/lang/Object;) → 自动 toString, 失败则 lightuserdata
/// - 其他对象 → lightuserdata
pub(crate) unsafe fn push_jni_arg(
    L: *mut ffi::lua_State,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
    env: *const std::ffi::c_void,
) {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => {
            ffi::lua_pushinteger(L, raw as ffi::lua_Integer);
            return;
        }
    };
    match sig.as_bytes()[0] {
        b'Z' => ffi::lua_pushboolean(L, if raw != 0 { 1 } else { 0 }),
        b'B' => ffi::lua_pushinteger(L, raw as i8 as ffi::lua_Integer),
        b'C' => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            let cs = std::ffi::CString::new(s).unwrap();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        b'S' => ffi::lua_pushinteger(L, raw as i16 as ffi::lua_Integer),
        b'I' => ffi::lua_pushinteger(L, raw as i32 as ffi::lua_Integer),
        b'J' => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
        b'F' => {
            let f = f32::from_bits(fp_raw as u32);
            ffi::lua_pushnumber(L, f as f64);
        }
        b'D' => {
            let d = f64::from_bits(fp_raw);
            ffi::lua_pushnumber(L, d);
        }
        b'L' | b'[' => {
            if raw == 0 {
                ffi::lua_pushnil(L);
            } else {
                ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
    }
}

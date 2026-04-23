use super::ffi;
use super::state::LuaState;
use std::sync::atomic::{AtomicU64, Ordering};

/// 当前 callback 线程的 JNIEnv (TLS-like, 用于 jstr 等 API)
std::thread_local! {
    static CURRENT_ENV: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(crate) fn set_current_env(env: *const std::ffi::c_void) {
    CURRENT_ENV.with(|c| c.set(env as usize));
}

pub(crate) fn clear_current_env() {
    CURRENT_ENV.with(|c| c.set(0));
}

fn get_current_env() -> *const std::ffi::c_void {
    CURRENT_ENV.with(|c| c.get() as *const std::ffi::c_void)
}

pub(crate) unsafe fn register_lua_apis(state: &LuaState) {
    state.register_fn("print", Some(lua_print));
    state.register_fn("jstr", Some(lua_jstr));
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
            // lightuserdata = Java 对象, 自动尝试 toString
            let ptr = ffi::lua_touserdata(L, i) as u64;
            let env = get_current_env();
            if ptr != 0 && !env.is_null() {
                if let Some(s) = jni_tostring(ptr, env) {
                    parts.push(s);
                    continue;
                }
            }
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
    let env = get_current_env();
    if env.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    match jni_tostring(ptr, env) {
        Some(s) => {
            let cs = std::ffi::CString::new(s).unwrap_or_default();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        None => ffi::lua_pushnil(L),
    }
    1
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
    // GetMethodID (vtable index 33)
    type GetMethodIdFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *const std::os::raw::c_char, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    // CallObjectMethodA (vtable index 36)
    type CallObjectMethodAFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> *mut std::ffi::c_void;
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

/// ctx:orig() — 通过 JNI 调用原始方法
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

    let ret = crate::jsapi::java::callback::invoke_original_jni(
        cb_ctx.env,
        cb_ctx.art_method,
        cb_ctx.class_global_ref,
        cb_ctx.this_obj,
        cb_ctx.return_type,
        cb_ctx.is_static,
        cb_ctx.jargs_ptr,
        cb_ctx.quick_trampoline,
        false,
    );

    push_return_value(L, ret, cb_ctx.return_type);
    1
}

unsafe fn push_return_value(
    L: *mut ffi::lua_State,
    raw: u64,
    return_type: u8,
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
            } else if !env.is_null() {
                // 对所有对象类型自动尝试 toString
                if let Some(s) = jni_tostring(raw, env) {
                    let cs = std::ffi::CString::new(s).unwrap_or_default();
                    ffi::lua_pushstring(L, cs.as_ptr());
                } else {
                    ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
                }
            } else {
                ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
    }
}

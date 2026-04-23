use super::ffi;
use super::api::{lua_to_jvalue, lua_string_to_jstring, push_jni_arg};

type JniEnv = crate::jsapi::java::jni_core::JniEnv;

/// JNI vtable 常用索引
const JNI_FIND_CLASS: usize = 6;
const JNI_GET_METHOD_ID: usize = 33;
const JNI_GET_STATIC_METHOD_ID: usize = 113;
const JNI_NEW_LOCAL_REF: usize = 25;
const JNI_DELETE_LOCAL_REF: usize = 23;
const JNI_EXCEPTION_CHECK: usize = 228;
const JNI_EXCEPTION_CLEAR: usize = 17;
const JNI_CALL_NONVIRTUAL_VOID_METHOD_A: usize = 93;
const JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A: usize = 96;
const JNI_CALL_NONVIRTUAL_INT_METHOD_A: usize = 99;
const JNI_CALL_NONVIRTUAL_LONG_METHOD_A: usize = 102;
const JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A: usize = 105;
const JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A: usize = 108;
const JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A: usize = 111;
const JNI_CALL_STATIC_VOID_METHOD_A: usize = 143;
const JNI_CALL_STATIC_BOOLEAN_METHOD_A: usize = 146;
const JNI_CALL_STATIC_INT_METHOD_A: usize = 149;
const JNI_CALL_STATIC_LONG_METHOD_A: usize = 152;
const JNI_CALL_STATIC_FLOAT_METHOD_A: usize = 155;
const JNI_CALL_STATIC_DOUBLE_METHOD_A: usize = 158;
const JNI_CALL_STATIC_OBJECT_METHOD_A: usize = 161;
const JNI_NEW_OBJECT_A: usize = 30;

unsafe fn jni_fn_ptr(env: JniEnv, idx: usize) -> *const std::ffi::c_void {
    crate::jsapi::java::jni_core::jni_fn_ptr(env, idx)
}

macro_rules! jfn {
    ($env:expr, $ty:ty, $idx:expr) => {
        std::mem::transmute::<*const std::ffi::c_void, $ty>(jni_fn_ptr($env, $idx))
    };
    ($env:expr, $idx:expr) => {
        std::mem::transmute(jni_fn_ptr($env, $idx))
    };
}

unsafe fn exc_check_clear(env: JniEnv) -> bool {
    let check: unsafe extern "C" fn(JniEnv) -> u8 = jfn!(env, JNI_EXCEPTION_CHECK);
    if check(env) != 0 {
        let clear: unsafe extern "C" fn(JniEnv) = jfn!(env, JNI_EXCEPTION_CLEAR);
        clear(env);
        true
    } else {
        false
    }
}

unsafe fn find_class(env: JniEnv, name: &str) -> *mut std::ffi::c_void {
    crate::jsapi::java::reflect::find_class_safe(env, &name.replace('.', "/"))
}

unsafe fn del_local(env: JniEnv, obj: *mut std::ffi::c_void) {
    if !obj.is_null() {
        let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) = jfn!(env, JNI_DELETE_LOCAL_REF);
        f(env, obj);
    }
}

/// Java._call(jptr, className, methodName, sig, ...)
/// 实例方法调用: CallNonvirtual*MethodA
pub(crate) unsafe extern "C" fn lua_jni_call(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    let jptr = ffi::lua_touserdata(L, 1) as u64;
    let cls_c = ffi::lua_tostring_ex(L, 2);
    let method_c = ffi::lua_tostring_ex(L, 3);
    let sig_c = ffi::lua_tostring_ex(L, 4);
    if cls_c.is_null() || method_c.is_null() || sig_c.is_null() || jptr == 0 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();
    let method_name = std::ffi::CStr::from_ptr(method_c).to_string_lossy();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy();

    let cls = find_class(env, &cls_name);
    if cls.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }

    let new_local: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void = jfn!(env, JNI_NEW_LOCAL_REF);
    let local_obj = new_local(env, jptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let get_mid: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const i8, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_GET_METHOD_ID);
    let cm = std::ffi::CString::new(method_name.as_ref()).unwrap_or_default();
    let cs = std::ffi::CString::new(sig.as_ref()).unwrap_or_default();
    let mid = get_mid(env, cls, cm.as_ptr() as *const i8, cs.as_ptr() as *const i8);
    if mid.is_null() || exc_check_clear(env) {
        del_local(env, local_obj);
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let param_types = crate::jsapi::java::callback::parse_jni_param_types(&sig);
    let return_type = crate::jsapi::java::callback::get_return_type_from_sig(&sig);
    let return_type_sig = crate::jsapi::java::callback::get_return_type_sig(&sig);

    let mut jargs: Vec<u64> = Vec::with_capacity(param_types.len());
    for (i, pt) in param_types.iter().enumerate() {
        let lua_idx = (5 + i) as i32;
        jargs.push(lua_to_jvalue(L, lua_idx, Some(pt.as_str()), env));
    }
    let jargs_ptr: *const std::ffi::c_void = if jargs.is_empty() {
        std::ptr::null()
    } else {
        jargs.as_ptr() as *const _
    };

    call_and_push_result(L, env, local_obj, cls, mid, jargs_ptr, return_type, &return_type_sig, false);
    del_local(env, local_obj);
    del_local(env, cls);
    1
}

/// Java._staticCall(className, methodName, sig, ...)
pub(crate) unsafe extern "C" fn lua_jni_static_call(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    let cls_c = ffi::lua_tostring_ex(L, 1);
    let method_c = ffi::lua_tostring_ex(L, 2);
    let sig_c = ffi::lua_tostring_ex(L, 3);
    if cls_c.is_null() || method_c.is_null() || sig_c.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();
    let method_name = std::ffi::CStr::from_ptr(method_c).to_string_lossy();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy();

    let cls = find_class(env, &cls_name);
    if cls.is_null() { ffi::lua_pushnil(L); return 1; }

    let get_mid: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const i8, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_GET_STATIC_METHOD_ID);
    let cm = std::ffi::CString::new(method_name.as_ref()).unwrap_or_default();
    let cs = std::ffi::CString::new(sig.as_ref()).unwrap_or_default();
    let mid = get_mid(env, cls, cm.as_ptr() as *const i8, cs.as_ptr() as *const i8);
    if mid.is_null() || exc_check_clear(env) {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let param_types = crate::jsapi::java::callback::parse_jni_param_types(&sig);
    let return_type = crate::jsapi::java::callback::get_return_type_from_sig(&sig);
    let return_type_sig = crate::jsapi::java::callback::get_return_type_sig(&sig);

    let mut jargs: Vec<u64> = Vec::with_capacity(param_types.len());
    for (i, pt) in param_types.iter().enumerate() {
        let lua_idx = (4 + i) as i32;
        jargs.push(lua_to_jvalue(L, lua_idx, Some(pt.as_str()), env));
    }
    let jargs_ptr: *const std::ffi::c_void = if jargs.is_empty() {
        std::ptr::null()
    } else {
        jargs.as_ptr() as *const _
    };

    call_and_push_result(L, env, std::ptr::null_mut(), cls, mid, jargs_ptr, return_type, &return_type_sig, true);
    del_local(env, cls);
    1
}

/// Java._new(className, sig, ...)
pub(crate) unsafe extern "C" fn lua_jni_new(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    let cls_c = ffi::lua_tostring_ex(L, 1);
    let sig_c = ffi::lua_tostring_ex(L, 2);
    if cls_c.is_null() || sig_c.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy();

    let cls = find_class(env, &cls_name);
    if cls.is_null() { ffi::lua_pushnil(L); return 1; }

    let get_mid: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const i8, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_GET_METHOD_ID);
    let cs = std::ffi::CString::new(sig.as_ref()).unwrap_or_default();
    let mid = get_mid(env, cls, c"<init>".as_ptr() as *const i8, cs.as_ptr() as *const i8);
    if mid.is_null() || exc_check_clear(env) {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let param_types = crate::jsapi::java::callback::parse_jni_param_types(&sig);
    let mut jargs: Vec<u64> = Vec::with_capacity(param_types.len());
    for (i, pt) in param_types.iter().enumerate() {
        let lua_idx = (3 + i) as i32;
        jargs.push(lua_to_jvalue(L, lua_idx, Some(pt.as_str()), env));
    }
    let jargs_ptr: *const std::ffi::c_void = if jargs.is_empty() {
        std::ptr::null()
    } else {
        jargs.as_ptr() as *const _
    };

    let new_obj: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> *mut std::ffi::c_void = jfn!(env, JNI_NEW_OBJECT_A);
    let obj = new_obj(env, cls, mid, jargs_ptr);
    if obj.is_null() || exc_check_clear(env) {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }
    del_local(env, cls);
    ffi::lua_pushlightuserdata(L, obj);
    1
}

/// Java._methods(className) → {{name=, sig=, isStatic=}, ...}
/// 轻量级实现: 只用 getName + getModifiers + getParameterTypes + getReturnType
/// 每个方法中间插入 ExceptionCheck 作为 ART suspend checkpoint
pub(crate) unsafe extern "C" fn lua_jni_methods(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let cls_c = ffi::lua_tostring_ex(L, 1);
    if cls_c.is_null() { ffi::lua_pushnil(L); return 1; }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();

    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    let cls = crate::jsapi::java::reflect::find_class_safe(env, &cls_name);
    if cls.is_null() { ffi::lua_pushnil(L); return 1; }

    let find_cls: unsafe extern "C" fn(JniEnv, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_FIND_CLASS);
    let get_mid: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const i8, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_GET_METHOD_ID);
    let call_obj: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> *mut std::ffi::c_void = jfn!(env, 36);
    let call_int: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> i32 = jfn!(env, 49);
    let get_str: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut u8) -> *const std::os::raw::c_char = jfn!(env, 169);
    let rel_str: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const std::os::raw::c_char) = jfn!(env, 170);
    let get_arr_len: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> i32 = jfn!(env, 171);
    let get_arr_elem: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, i32) -> *mut std::ffi::c_void = jfn!(env, 173);

    let class_cls = find_cls(env, c"java/lang/Class".as_ptr() as *const i8);
    let method_cls = find_cls(env, c"java/lang/reflect/Method".as_ptr() as *const i8);
    if class_cls.is_null() || method_cls.is_null() { exc_check_clear(env); ffi::lua_pushnil(L); return 1; }

    let get_declared = get_mid(env, class_cls, c"getDeclaredMethods".as_ptr() as *const i8, c"()[Ljava/lang/reflect/Method;".as_ptr() as *const i8);
    let get_name = get_mid(env, method_cls, c"getName".as_ptr() as *const i8, c"()Ljava/lang/String;".as_ptr() as *const i8);
    let get_mods = get_mid(env, method_cls, c"getModifiers".as_ptr() as *const i8, c"()I".as_ptr() as *const i8);
    let get_params = get_mid(env, method_cls, c"getParameterTypes".as_ptr() as *const i8, c"()[Ljava/lang/Class;".as_ptr() as *const i8);
    let get_ret = get_mid(env, method_cls, c"getReturnType".as_ptr() as *const i8, c"()Ljava/lang/Class;".as_ptr() as *const i8);
    let cls_get_name = get_mid(env, class_cls, c"getName".as_ptr() as *const i8, c"()Ljava/lang/String;".as_ptr() as *const i8);
    if get_declared.is_null() || get_name.is_null() || get_mods.is_null() || get_params.is_null() || get_ret.is_null() || cls_get_name.is_null() {
        exc_check_clear(env);
        ffi::lua_pushnil(L);
        return 1;
    }

    let methods_arr = call_obj(env, cls, get_declared, std::ptr::null());
    if methods_arr.is_null() { exc_check_clear(env); ffi::lua_pushnil(L); return 1; }
    let len = get_arr_len(env, methods_arr);

    ffi::lua_createtable(L, len, 0);
    let mut idx = 1i64;

    for i in 0..len {
        // ART checkpoint: 每个方法间让 ART 有机会 suspend
        exc_check_clear(env);

        let method_obj = get_arr_elem(env, methods_arr, i);
        if method_obj.is_null() { continue; }

        // getName
        let name_jstr = call_obj(env, method_obj, get_name, std::ptr::null());
        if name_jstr.is_null() { continue; }
        let name_c = get_str(env, name_jstr, std::ptr::null_mut());
        if name_c.is_null() { continue; }
        let name = std::ffi::CStr::from_ptr(name_c).to_string_lossy().into_owned();
        rel_str(env, name_jstr, name_c);

        // getModifiers
        let modifiers = call_int(env, method_obj, get_mods, std::ptr::null());
        let is_static = (modifiers & 0x0008) != 0;

        // 构建 JNI 签名: getParameterTypes + getReturnType
        let mut sig = String::from("(");
        let param_arr = call_obj(env, method_obj, get_params, std::ptr::null());
        if !param_arr.is_null() {
            let plen = get_arr_len(env, param_arr);
            for j in 0..plen {
                let pcls = get_arr_elem(env, param_arr, j);
                if pcls.is_null() { continue; }
                let pn_jstr = call_obj(env, pcls, cls_get_name, std::ptr::null());
                if !pn_jstr.is_null() {
                    let pc = get_str(env, pn_jstr, std::ptr::null_mut());
                    if !pc.is_null() {
                        let pname = std::ffi::CStr::from_ptr(pc).to_string_lossy();
                        sig.push_str(&crate::jsapi::java::reflect::java_type_to_jni(&pname));
                        rel_str(env, pn_jstr, pc);
                    }
                }
            }
        }
        sig.push(')');

        let ret_cls = call_obj(env, method_obj, get_ret, std::ptr::null());
        if !ret_cls.is_null() {
            let rn_jstr = call_obj(env, ret_cls, cls_get_name, std::ptr::null());
            if !rn_jstr.is_null() {
                let rc = get_str(env, rn_jstr, std::ptr::null_mut());
                if !rc.is_null() {
                    let rname = std::ffi::CStr::from_ptr(rc).to_string_lossy();
                    sig.push_str(&crate::jsapi::java::reflect::java_type_to_jni(&rname));
                    rel_str(env, rn_jstr, rc);
                }
            }
        }

        // push {name=, sig=, isStatic=}
        ffi::lua_createtable(L, 0, 3);
        let name_cs = std::ffi::CString::new(name.as_str()).unwrap_or_default();
        ffi::lua_pushstring(L, name_cs.as_ptr());
        ffi::lua_setfield(L, -2, c"name".as_ptr());
        let sig_cs = std::ffi::CString::new(sig.as_str()).unwrap_or_default();
        ffi::lua_pushstring(L, sig_cs.as_ptr());
        ffi::lua_setfield(L, -2, c"sig".as_ptr());
        ffi::lua_pushboolean(L, if is_static { 1 } else { 0 });
        ffi::lua_setfield(L, -2, c"isStatic".as_ptr());
        ffi::lua_rawseti(L, -2, idx);
        idx += 1;
    }
    1
}

/// 执行 JNI 调用并 push 结果到 Lua 栈
unsafe fn call_and_push_result(
    L: *mut ffi::lua_State,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
    mid: *mut std::ffi::c_void,
    args: *const std::ffi::c_void,
    return_type: u8,
    return_type_sig: &str,
    is_static: bool,
) {
    macro_rules! call_jni {
        ($ret_ty:ty, $idx:expr, $static_idx:expr) => {{
            if is_static {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty = jfn!(env, $static_idx);
                f(env, cls, mid, args)
            } else {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty = jfn!(env, $idx);
                f(env, obj, cls, mid, args)
            }
        }};
    }

    match return_type {
        b'V' => {
            if is_static {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) = jfn!(env, JNI_CALL_STATIC_VOID_METHOD_A);
                f(env, cls, mid, args);
            } else {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) = jfn!(env, JNI_CALL_NONVIRTUAL_VOID_METHOD_A);
                f(env, obj, cls, mid, args);
            }
            exc_check_clear(env);
            ffi::lua_pushnil(L);
        }
        b'Z' => {
            let r = call_jni!(u8, JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A, JNI_CALL_STATIC_BOOLEAN_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushboolean(L, r as i32);
        }
        b'I' | b'B' | b'C' | b'S' => {
            let r = call_jni!(i32, JNI_CALL_NONVIRTUAL_INT_METHOD_A, JNI_CALL_STATIC_INT_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushinteger(L, r as ffi::lua_Integer);
        }
        b'J' => {
            let r = call_jni!(i64, JNI_CALL_NONVIRTUAL_LONG_METHOD_A, JNI_CALL_STATIC_LONG_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushinteger(L, r as ffi::lua_Integer);
        }
        b'F' => {
            let r = call_jni!(f32, JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A, JNI_CALL_STATIC_FLOAT_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushnumber(L, r as f64);
        }
        b'D' => {
            let r = call_jni!(f64, JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A, JNI_CALL_STATIC_DOUBLE_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushnumber(L, r);
        }
        b'L' | b'[' => {
            let r = call_jni!(*mut std::ffi::c_void, JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A, JNI_CALL_STATIC_OBJECT_METHOD_A);
            exc_check_clear(env);
            if r.is_null() {
                ffi::lua_pushnil(L);
            } else {
                // 返回 lightuserdata (可以传给 jstr 或其他方法)
                ffi::lua_pushlightuserdata(L, r);
            }
        }
        _ => ffi::lua_pushnil(L),
    }
}

unsafe fn get_env(L: *mut ffi::lua_State) -> JniEnv {
    let env_ptr = super::api::get_current_env();
    if !env_ptr.is_null() {
        return env_ptr as JniEnv;
    }
    match crate::jsapi::java::jni_core::get_thread_env() {
        Ok(e) => e,
        Err(_) => std::ptr::null_mut(),
    }
}

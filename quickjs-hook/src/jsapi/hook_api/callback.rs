//! Hook callback wrapper (cross-thread safety, context building) — replace mode
//!
//! The thunk saves context and calls on_enter, then restores x0 and returns.
//! The callback can optionally call the original function via callOriginal().

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{invoke_hook_callback_common, set_js_u64_property};
use crate::value::JSValue;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::registry::HOOK_REGISTRY;

// Global state for the currently executing native hook callback.
// Protected by JS_ENGINE lock (single-threaded JS execution).
static CURRENT_NATIVE_CTX_PTR: AtomicUsize = AtomicUsize::new(0);
static CURRENT_NATIVE_TRAMPOLINE: AtomicU64 = AtomicU64::new(0);

/// Hook callback that calls the JS function (replace mode)
pub(crate) unsafe extern "C" fn hook_callback_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let target_addr = user_data as u64;

    // Copy callback data then release the lock before QuickJS operations.
    let (ctx_usize, callback_bytes, trampoline) = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let hook_data = match registry.get(&target_addr) {
            Some(d) => d,
            None => return,
        };
        (hook_data.ctx, hook_data.callback_bytes, hook_data.trampoline)
    }; // HOOK_REGISTRY lock released here

    // Set global state for js_native_call_original
    CURRENT_NATIVE_CTX_PTR.store(ctx_ptr as usize, Ordering::Relaxed);
    CURRENT_NATIVE_TRAMPOLINE.store(trampoline, Ordering::Relaxed);

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "hook",
        target_addr,
        // 构建 JS 上下文对象：x0-x30, sp, pc, trampoline, callOriginal()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;

            for i in 0..31 {
                let prop_name = format!("x{}", i);
                set_js_u64_property(ctx, js_ctx, &prop_name, hook_ctx.x[i]);
            }
            set_js_u64_property(ctx, js_ctx, "sp", hook_ctx.sp);
            set_js_u64_property(ctx, js_ctx, "pc", hook_ctx.pc);
            set_js_u64_property(ctx, js_ctx, "trampoline", trampoline);

            let cname = CString::new("callOriginal").unwrap();
            let func_val = ffi::qjs_new_cfunction(ctx, Some(js_native_call_original), cname.as_ptr(), 0);
            JSValue(js_ctx).set_property(ctx, "callOriginal", JSValue(func_val));

            js_ctx
        },
        // 处理返回值：从上下文对象读回 x0（replace mode 只恢复 x0）
        |ctx, js_ctx, _result| {
            let cprop = CString::new("x0").unwrap();
            let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
            let val = ffi::qjs_get_property(ctx, js_ctx, atom);
            ffi::JS_FreeAtom(ctx, atom);

            let js_val = JSValue(val);
            if let Some(new_val) = js_val.to_u64(ctx) {
                (*ctx_ptr).x[0] = new_val;
            }
            js_val.free(ctx);
        },
    );

    // Clear global state
    CURRENT_NATIVE_CTX_PTR.store(0, Ordering::Relaxed);
    CURRENT_NATIVE_TRAMPOLINE.store(0, Ordering::Relaxed);
}

/// JS CFunction: ctx.callOriginal()
/// Restores registers from HookContext and calls the trampoline (original function).
/// Returns the result as BigUint64, also writes it to ctx.x[0].
unsafe extern "C" fn js_native_call_original(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let ctx_ptr = CURRENT_NATIVE_CTX_PTR.load(Ordering::Relaxed) as *mut hook_ffi::HookContext;
    let trampoline = CURRENT_NATIVE_TRAMPOLINE.load(Ordering::Relaxed);

    if ctx_ptr.is_null() || trampoline == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);

    // Write result back to HookContext.x[0] so the thunk's final RET returns this value
    (*ctx_ptr).x[0] = result;

    // Return value: Number (≤2^53) or BigUint64
    if result <= (1u64 << 53) {
        ffi::qjs_new_int64(ctx, result as i64)
    } else {
        ffi::JS_NewBigUint64(ctx, result)
    }
}

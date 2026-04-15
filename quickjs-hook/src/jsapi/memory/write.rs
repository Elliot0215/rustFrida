//! Memory write operations

use super::helpers::{get_addr_this_or_arg, write_with_perm};
use super::writest::extract_bytes;
use crate::ffi;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

/// 生成 Memory.writeXXX(ptr, value) 和 ptr.writeXXX(value) 双风格 write 函数。
/// rem_argv 指向 value（自动剥离 Memory 风格的 addr 参数）。
macro_rules! define_memory_write {
    ($name:ident, $js_name:literal, $rust_type:ty, $size:expr,
     ($ctx_id:ident, $argv_id:ident) => $extract:expr) => {
        pub(super) unsafe extern "C" fn $name(
            $ctx_id: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg($ctx_id, this, argc, argv) {
                Some(v) => v,
                None => return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires a pointer\0").as_ptr() as *const _,
                ),
            };
            if rem_argc < 1 {
                return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires value argument\0").as_ptr() as *const _,
                );
            }
            let $argv_id = rem_argv;
            if !is_addr_accessible(addr, $size) {
                return ffi::JS_ThrowRangeError($ctx_id, b"Invalid memory address\0".as_ptr() as *const _);
            }
            let val: $rust_type = $extract;
            if !write_with_perm(addr, $size, || {
                std::ptr::write_unaligned(addr as *mut $rust_type, val);
            }) {
                return ffi::JS_ThrowRangeError(
                    $ctx_id,
                    concat!($js_name, "(): target page is not writable; call Memory.protect(addr, size, \"rwx\") first\0").as_ptr() as *const _,
                );
            }
            JSValue::undefined().raw()
        }
    };
}

define_memory_write!(memory_write_u8, "writeU8", u8, 1,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u8);
define_memory_write!(memory_write_u16, "writeU16", u16, 2,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u16);
define_memory_write!(memory_write_u32, "writeU32", u32, 4,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u32);
define_memory_write!(memory_write_u64, "writeU64", u64, 8,
    (ctx, argv) => JSValue(*argv).to_u64(ctx).unwrap_or(0));

/// Memory.writePointer(ptr, value) / ptr.writePointer(value)
pub(super) unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as writeU64
    memory_write_u64(ctx, this, argc, argv)
}

/// `Memory.writeBytes(ptr, bytes, stealth?)` / `ptr.writeBytes(bytes, stealth?)`
///
/// Multi-byte write with an optional stealth flag:
///   - `stealth=0` or omitted: classic mprotect RWX → memcpy → restore
///   - `stealth=1`: kernel wxshadow PATCH (shadow page visible only to I-fetch)
///
/// For the "1 instruction → N instruction" replacement semantics (PC-rel
/// aware, atomic B→slot in recomp page), use `writest()` (stealth-2) instead.
pub(super) unsafe extern "C" fn memory_write_bytes(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg(ctx, this, argc, argv) {
        Some(v) => v,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"writeBytes() requires a pointer\0".as_ptr() as *const _,
            );
        }
    };
    if rem_argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"writeBytes() requires bytes argument\0".as_ptr() as *const _,
        );
    }

    let bytes = match extract_bytes(ctx, JSValue(*rem_argv)) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if bytes.is_empty() {
        return JSValue::undefined().raw();
    }

    let stealth = if rem_argc >= 2 {
        JSValue(*rem_argv.add(1)).to_i64(ctx).unwrap_or(0)
    } else {
        0
    };

    match stealth {
        0 => {
            if !is_addr_accessible(addr, bytes.len()) {
                return ffi::JS_ThrowRangeError(
                    ctx,
                    b"writeBytes: invalid memory address\0".as_ptr() as *const _,
                );
            }
            let src = bytes.as_ptr();
            let len = bytes.len();
            if !write_with_perm(addr, len, || {
                std::ptr::copy_nonoverlapping(src, addr as *mut u8, len);
            }) {
                return ffi::JS_ThrowRangeError(
                    ctx,
                    b"writeBytes: target page is not writable; call Memory.protect(addr, size, \"rwx\") first, or use writeBytes(bytes, 1)/writest() for stealth code patch\0".as_ptr() as *const _,
                );
            }
            ffi::hook::hook_flush_cache(addr as *mut _, len);
            JSValue::undefined().raw()
        }
        1 => {
            let rc = ffi::hook::wxshadow_patch(
                addr as *mut std::ffi::c_void,
                bytes.as_ptr() as *const std::ffi::c_void,
                bytes.len(),
            );
            if rc != 0 {
                let msg = format!("writeBytes(stealth=1): wxshadow_patch rc={}\0", rc);
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"%s\0".as_ptr() as *const _,
                    msg.as_ptr(),
                );
            }
            ffi::hook::hook_flush_cache(addr as *mut _, bytes.len());
            JSValue::undefined().raw()
        }
        other => {
            let msg = format!(
                "writeBytes: unsupported stealth mode {} (expected 0 or 1; use writest for mode 2)\0",
                other
            );
            ffi::JS_ThrowInternalError(ctx, b"%s\0".as_ptr() as *const _, msg.as_ptr())
        }
    }
}

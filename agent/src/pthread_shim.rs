use libc::{
    c_int, c_long, c_void, mmap, pthread_t, timespec, SYS_clone, SYS_exit, SYS_nanosleep, CLONE_FILES, CLONE_FS,
    CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};
use std::arch::asm;

const STACK_SIZE: usize = 1024 * 1024;

struct ShimThreadStart {
    start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
}

#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    thread: *mut pthread_t,
    _attr: *const c_void,
    start: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    arg: *mut c_void,
) -> c_int {
    let Some(start) = start else {
        return libc::EINVAL;
    };
    let stack = mmap(
        std::ptr::null_mut(),
        STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if stack == libc::MAP_FAILED {
        return libc::ENOMEM;
    }
    let state = Box::into_raw(Box::new(ShimThreadStart { start, arg }));
    let child_stack = (stack as *mut u8).add(STACK_SIZE) as *mut usize;
    let flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM) as u64;
    match raw_clone(shim_thread_entry as *mut usize, state as usize, flags, child_stack) {
        Ok(tid) => {
            if !thread.is_null() {
                *thread = tid as pthread_t;
            }
            0
        }
        Err(errno) => {
            drop(Box::from_raw(state));
            errno
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_detach(_thread: pthread_t) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    let mut result: c_long;
    asm!(
        "svc 0x0",
        in("x8") SYS_nanosleep,
        inout("x0") req as usize => result,
        in("x1") rem as usize,
        options(nostack, preserves_flags),
    );
    if result < 0 {
        -1
    } else {
        result as c_int
    }
}

unsafe fn raw_clone(child_func: *mut usize, arg: usize, flags: u64, child_stack: *mut usize) -> Result<i32, c_int> {
    let mut result: i64;

    *(child_stack.sub(1)) = child_func as usize;
    *(child_stack.sub(2)) = arg;

    asm!(
        "svc 0x0",
        "cbnz x0, 1f",
        "ldp x0, x1, [sp], #16",
        "blr x1",
        "mov x8, {exit_syscall}",
        "mov x0, #0",
        "svc 0x0",
        "1:",
        in("x8") SYS_clone,
        inout("x0") flags => result,
        in("x1") child_stack.sub(2),
        in("x2") 0usize,
        in("x3") 0usize,
        in("x4") 0usize,
        exit_syscall = const SYS_exit,
        options(nostack, preserves_flags),
        clobber_abi("C"),
    );

    if result < 0 {
        Err((-result) as c_int)
    } else {
        Ok(result as i32)
    }
}

extern "C" fn shim_thread_entry(arg: usize) -> c_int {
    let state = unsafe { Box::from_raw(arg as *mut ShimThreadStart) };
    unsafe {
        (state.start)(state.arg);
    }
    0
}

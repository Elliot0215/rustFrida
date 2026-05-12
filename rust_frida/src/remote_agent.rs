#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use nix::sys::ptrace;
use nix::unistd::Pid;
use std::sync::atomic::Ordering;

use crate::process::{attach_to_process, call_target_function, read_memory, write_bytes};
use crate::session::Session;
use crate::types::{FridaLibcApi, RustFridaLoaderContext};

pub(crate) fn eval_js_on_main_thread(
    session: &Session,
    script: &str,
    filename: &str,
    init_engine: bool,
) -> Result<(), String> {
    let pid = session.pid.load(Ordering::Acquire);
    if pid <= 0 {
        return Err("remote eval: session pid missing".to_string());
    }
    let loader_ctx_addr = session.loader_ctx_addr.load(Ordering::Acquire);
    let eval_fn = session.agent_current_thread_eval_impl.load(Ordering::Acquire);
    if loader_ctx_addr == 0 || eval_fn == 0 {
        return Err("remote eval: agent current-thread entry missing".to_string());
    }

    attach_to_process(pid)?;
    let result = eval_js_attached(
        pid,
        loader_ctx_addr as usize,
        eval_fn as usize,
        script,
        filename,
        init_engine,
    );
    let detach_result = ptrace::detach(Pid::from_raw(pid), None).map_err(|e| e.to_string());
    match (result, detach_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) => Err(e),
        (Ok(()), Err(e)) => Err(format!("remote eval detach 失败: {}", e)),
    }
}

fn eval_js_attached(
    pid: i32,
    loader_ctx_addr: usize,
    eval_fn: usize,
    script: &str,
    filename: &str,
    init_engine: bool,
) -> Result<(), String> {
    let loader_ctx: RustFridaLoaderContext = read_memory(pid, loader_ctx_addr)?;
    let libc_api: FridaLibcApi = read_memory(pid, loader_ctx.libc as usize)?;
    if libc_api.mmap_fn == 0 || libc_api.munmap_fn == 0 {
        return Err("remote eval: loader libc mmap/munmap missing".to_string());
    }

    let total_len = align_up(script.len().max(1) + filename.len().max(1), 16);
    let remote = call_target_function(
        pid,
        libc_api.mmap_fn as usize,
        &[
            0,
            total_len,
            (libc::PROT_READ | libc::PROT_WRITE) as usize,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize,
            usize::MAX,
            0,
        ],
        None,
    )?;
    if remote == usize::MAX || remote == 0 {
        return Err("remote eval: target mmap failed".to_string());
    }

    let script_addr = remote;
    let filename_addr = remote + script.len().max(1);
    let call_result = (|| {
        if !script.is_empty() {
            write_bytes(pid, script_addr, script.as_bytes())?;
        }
        if !filename.is_empty() {
            write_bytes(pid, filename_addr, filename.as_bytes())?;
        }
        let ret = call_target_function(
            pid,
            eval_fn,
            &[
                script_addr,
                script.len(),
                filename_addr,
                filename.len(),
                if init_engine { 1 } else { 0 },
            ],
            None,
        )?;
        if ret != 0 {
            return Err(format!("remote eval: agent returned {}", ret));
        }
        Ok(())
    })();

    let _ = call_target_function(pid, libc_api.munmap_fn as usize, &[remote, total_len], None);
    call_result
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

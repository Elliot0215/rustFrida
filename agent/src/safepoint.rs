//! 全线程 PC/LR 安全点检查
//!
//! 用于 cleanup 前确认没有任何线程的 PC 或 LR 落在 hook_engine 扩展 pool
//! 或 recomp 页范围内，再做 munmap，避免 "pc=lr=unmapped" 崩溃。
//!
//! 机制：
//!   1. 给每个工作线程发 SIGRTMIN+7
//!   2. 信号 handler 读 ucontext 的 pc 和 x30 (LR)，写入全局 atomic
//!   3. 主线程 spin 等 handler 标记完成，检查 pc/lr 是否在保护区间
//!   4. 任一线程命中区间 → 短暂 sleep 后重试；超时则放弃 munmap (leak)
//!
//! ucontext_t 布局 (aarch64 bionic):
//!   mcontext_t @ +176，regs[31] @ +184 (x0..x30)，sp @ +432，pc @ +440
//!   x30 (LR) @ +184 + 30*8 = +424

use crate::communication::log_msg;
use libc::{
    c_int, c_void, gettid, pid_t, sigaction, sigemptyset, siginfo_t, syscall, SYS_tgkill, SA_RESTART, SA_SIGINFO,
};
use std::fs;
use std::mem::zeroed;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 用于探测的 RT 信号。Bionic SIGRTMIN=32，+7=39，ART/pthread 未占用
fn probe_signal() -> c_int {
    unsafe { libc::SIGRTMIN() + 7 }
}

static PROBE_INSTALLED: AtomicBool = AtomicBool::new(false);
static PROBE_PC: AtomicU64 = AtomicU64::new(0);
static PROBE_LR: AtomicU64 = AtomicU64::new(0);
static PROBE_DONE: AtomicBool = AtomicBool::new(false);
static PROBE_BUSY: Mutex<()> = Mutex::new(());

/// 信号 handler：读 PC 和 LR，写入 atomic
extern "C" fn probe_handler(_sig: c_int, _info: *mut siginfo_t, ctx: *mut c_void) {
    if ctx.is_null() {
        PROBE_DONE.store(true, Ordering::SeqCst);
        return;
    }
    unsafe {
        let uc = ctx as *const u8;
        let pc = *(uc.add(176 + 264) as *const u64); // mcontext + 264
        let lr = *(uc.add(176 + 8 + 30 * 8) as *const u64); // regs[30]
        PROBE_PC.store(pc, Ordering::SeqCst);
        PROBE_LR.store(lr, Ordering::SeqCst);
        PROBE_DONE.store(true, Ordering::SeqCst);
    }
}

fn install_probe_handler() {
    if PROBE_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        let mut sa: sigaction = zeroed();
        sa.sa_sigaction = probe_handler as usize;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&mut sa.sa_mask);
        if sigaction(probe_signal(), &sa, std::ptr::null_mut()) != 0 {
            log_msg(format!(
                "[safepoint] sigaction install failed: errno={}",
                std::io::Error::last_os_error()
            ));
        }
    }
}

/// 一次性对某 tid 发信号并等待 handler 标记，返回 (pc, lr)
/// 超时或 tid 已死返回 None
fn probe_one_thread(tid: pid_t, pid: pid_t) -> Option<(u64, u64)> {
    PROBE_DONE.store(false, Ordering::SeqCst);
    PROBE_PC.store(0, Ordering::SeqCst);
    PROBE_LR.store(0, Ordering::SeqCst);
    let sig = probe_signal();
    let rc = unsafe { syscall(SYS_tgkill, pid, tid, sig) };
    if rc != 0 {
        // 线程可能刚退出；忽略
        return None;
    }
    let start = Instant::now();
    loop {
        if PROBE_DONE.load(Ordering::SeqCst) {
            return Some((PROBE_PC.load(Ordering::SeqCst), PROBE_LR.load(Ordering::SeqCst)));
        }
        if start.elapsed() > Duration::from_millis(50) {
            return None; // 信号未被接收 / 线程阻塞在不可中断状态
        }
        std::hint::spin_loop();
    }
}

fn in_any_range(addr: u64, ranges: &[(u64, u64)]) -> bool {
    if addr == 0 {
        return false;
    }
    for &(base, size) in ranges {
        if addr >= base && addr < base + size {
            return true;
        }
    }
    false
}

/// 逐线程检查 PC 和 LR 是否落在保护区间。返回 (ok, busy_pc_hits, busy_lr_hits, probed, skipped)
fn check_all_threads(ranges: &[(u64, u64)]) -> (bool, usize, usize, usize, usize) {
    let pid = unsafe { libc::getpid() };
    let self_tid = unsafe { gettid() };
    let dir = match fs::read_dir("/proc/self/task") {
        Ok(d) => d,
        Err(_) => return (true, 0, 0, 0, 0),
    };
    let mut pc_hits = 0usize;
    let mut lr_hits = 0usize;
    let mut probed = 0usize;
    let mut skipped = 0usize;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        let tid: pid_t = match s.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if tid == self_tid {
            continue;
        }
        match probe_one_thread(tid, pid) {
            Some((pc, lr)) => {
                probed += 1;
                if in_any_range(pc, ranges) {
                    pc_hits += 1;
                }
                if in_any_range(lr, ranges) {
                    lr_hits += 1;
                }
            }
            None => skipped += 1,
        }
    }
    let ok = pc_hits == 0 && lr_hits == 0;
    (ok, pc_hits, lr_hits, probed, skipped)
}

/// 等待所有线程 PC/LR 离开保护区间。超时返回 false (应放弃 munmap)
pub fn wait_until_clean(ranges: &[(u64, u64)], total_timeout_ms: u64) -> bool {
    if ranges.is_empty() {
        return true;
    }
    install_probe_handler();
    // 同一进程只允许一个 probe 同时跑（PROBE_PC/LR atomic 是共享的）
    let _lock = match PROBE_BUSY.try_lock() {
        Ok(g) => g,
        Err(_) => {
            log_msg("[safepoint] another probe already running, skip".to_string());
            return false;
        }
    };

    let start = Instant::now();
    let mut attempt = 0usize;
    let mut last_report = Instant::now();
    loop {
        attempt += 1;
        let (ok, pc, lr, probed, skipped) = check_all_threads(ranges);
        if ok {
            log_msg(format!(
                "[safepoint] clean after {} attempt(s), probed={} skipped={}, elapsed={}ms",
                attempt,
                probed,
                skipped,
                start.elapsed().as_millis()
            ));
            return true;
        }
        let elapsed = start.elapsed().as_millis() as u64;
        if elapsed > total_timeout_ms {
            log_msg(format!(
                "[safepoint] TIMEOUT after {}ms (attempt {}) — pc_hits={} lr_hits={} probed={} skipped={}",
                elapsed, attempt, pc, lr, probed, skipped
            ));
            return false;
        }
        // 周期性进度日志（每 200ms）
        if last_report.elapsed() > Duration::from_millis(200) {
            log_msg(format!(
                "[safepoint] still busy after {}ms: pc_hits={} lr_hits={}",
                elapsed, pc, lr
            ));
            last_report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

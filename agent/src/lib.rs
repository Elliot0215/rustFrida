#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod jhook;
mod gumlibc;
mod writer;
mod relocater;
mod trace;
mod exec_mem;
mod communication;
mod crash_handler;

#[cfg(feature = "frida-gum")]
mod stalker;
#[cfg(feature = "frida-gum")]
mod memory_dump;
#[cfg(feature = "qbdi")]
mod qbdi_trace;
#[cfg(feature = "quickjs")]
mod quickjs_loader;

use crate::jhook::jhook;
use crate::communication::{connect_socket, flush_cached_logs, log_msg, write_stream, GLOBAL_STREAM, SOCKET_NAME};
use crate::crash_handler::{install_crash_handlers, install_panic_hook};
use libc::{c_int, kill, pid_t, SIGSTOP};
use std::ffi::c_void;
use std::io::BufRead;
use std::io::BufReader;
use std::ptr::null_mut;
use std::process;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub use exec_mem::ExecMem;

// 定义我们自己的Result类型，错误统一为String
type Result<T> = std::result::Result<T, String>;

// StringTable 结构定义（需要和 main.rs 中的定义完全一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StringTable {
    pub socket_name: u64,
    pub socket_name_len: u32,
    pub hello_msg: u64,
    pub hello_msg_len: u32,
    pub sym_name: u64,
    pub sym_name_len: u32,
    pub pthread_err: u64,
    pub pthread_err_len: u32,
    pub dlsym_err: u64,
    pub dlsym_err_len: u32,
    pub proc_path: u64,
    pub proc_path_len: u32,
    pub cmdline: u64,
    pub cmdline_len: u32,
    pub output_path: u64,
    pub output_path_len: u32,
}

impl StringTable {
    /// 从指针地址读取字符串（不包含末尾的 NULL）
    unsafe fn read_string(&self, addr: u64, len: u32) -> Option<String> {
        if addr == 0 || len == 0 {
            return None;
        }
        let ptr = addr as *const u8;
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        // 去掉末尾的 NULL 字符
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        String::from_utf8(slice[..end].to_vec()).ok()
    }

    /// 获取 socket_name
    pub unsafe fn get_socket_name(&self) -> Option<String> {
        self.read_string(self.socket_name, self.socket_name_len)
    }

    /// 获取 cmdline
    pub unsafe fn get_cmdline(&self) -> Option<String> {
        self.read_string(self.cmdline, self.cmdline_len)
    }

    /// 获取 output_path
    pub unsafe fn get_output_path(&self) -> Option<String> {
        self.read_string(self.output_path, self.output_path_len)
    }
}

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);
pub static OUTPUT_PATH: OnceLock<String> = OnceLock::new();

#[no_mangle]
pub extern "C" fn hello_entry(string_table: *mut c_void) -> *mut c_void {
    // 安装Rust panic hook（需要在最前面，捕获Rust层面的panic）
    install_panic_hook();
    // 安装崩溃信号处理器（捕获SIGSEGV等信号）
    install_crash_handlers();

    unsafe {
        // 解析 StringTable 结构
        let string_table = string_table as *const StringTable;
        let table = &*string_table;

        // 读取动态 socket 名（rust_frida_{pid}）并保存，connect_socket() 将使用它
        if let Some(sock) = table.get_socket_name() {
            if sock != "novalue" {
                let _ = SOCKET_NAME.set(sock);
            }
        }

        // 读取 output_path 并保存到全局变量
        if let Some(output) = table.get_output_path() {
            if output != "novalue" {
                let _ = OUTPUT_PATH.set(output.clone());
                // log_msg(format!("Output path: {}\n", output));
            }
        }

        // 读取 cmdline 参数
        if let Some(cmd) = table.get_cmdline() {
            if cmd != "novalue" {
                process_cmd(&cmd);
            }
        }
    }

    unsafe {
        let name = std::ffi::CString::new("wwb").unwrap();
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }


    // Connect and split into read/write halves so BufReader and Mutex-guarded writes
    // can operate concurrently on the same full-duplex Unix socket.
    let sock = connect_socket().expect("wwb connect socket failed!!!");
    let write_half = sock.try_clone().expect("stream clone failed");
    GLOBAL_STREAM.set(std::sync::Mutex::new(write_half)).unwrap();
    write_stream(b"HELLO_AGENT\n");
    std::thread::sleep(Duration::from_millis(100));
    flush_cached_logs();

    // 循环等待命令：BufReader + read_line 确保任意长度命令完整接收（无截断）
    let mut reader = BufReader::new(sock);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // 连接关闭（EOF）
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    process_cmd(trimmed);
                }
                if SHOULD_EXIT.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(e) => {
                // 读取错误
                write_stream(format!("读取命令错误: {}\n", e).as_bytes());
                break;
            }
        }
    }
    null_mut()
}

fn process_cmd(command: &str) {
    match command.split_whitespace().next() {
        Some("trace") => {
            let tid = command.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            std::thread::spawn(move || {
                match trace::gum_modify_thread(tid) {
                    Ok(pid) => {
                        write_stream(format!("clone success {}", pid).as_bytes());
                    }
                    Err(e) => {
                        write_stream(format!("error: {}", e).as_bytes());
                    }
                }
                unsafe { kill(process::id() as pid_t, SIGSTOP) }
            });
        },
        Some("jhook") => {
            std::thread::spawn(|| {
                match jhook() {
                    Ok(_) => {},
                    Err(e) => {
                        write_stream(format!("{}", e).as_bytes());
                    }
                }
            });
        },
        #[cfg(feature = "frida-gum")]
        Some("stalker") => {
            let tid = command.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            stalker::follow(tid)
        },
        #[cfg(feature = "frida-gum")]
        Some("hfl") => {
            let mut cmds = command.split_whitespace();
            let md = cmds.nth(1).unwrap();
            let offset = cmds.next().and_then(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                usize::from_str_radix(s, 16).ok()
            }).unwrap_or(0);
            stalker::hfollow(md, offset)
        },
        #[cfg(feature = "qbdi")]
        Some("qfl") => {
            let mut cmds = command.split_whitespace();
            let md = cmds.nth(1).unwrap();
            let offset = cmds.next().and_then(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                usize::from_str_radix(s, 16).ok()
            }).unwrap_or(0);
            qbdi_trace::qfollow(md, offset)
        },
        #[cfg(feature = "quickjs")]
        Some("jsinit") => {
            match quickjs_loader::init() {
                Ok(_) => log_msg("[quickjs] Engine initialized\n".to_string()),
                Err(e) => log_msg(format!("[quickjs] Init error: {}\n", e)),
            }
        },
        #[cfg(feature = "quickjs")]
        Some("loadjs") => {
            // Extract the script (everything after "loadjs ")
            let script = command.strip_prefix("loadjs").unwrap_or("").trim().to_string();
            if script.is_empty() {
                log_msg("[quickjs] Error: empty script\n".to_string());
            } else {
                // Run in a separate thread to avoid blocking
                std::thread::spawn(move || {
                    match quickjs_loader::execute_script(&script) {
                        Ok(_) => log_msg("[quickjs] Script executed successfully\n".to_string()),
                        Err(e) => log_msg(format!("[quickjs] Script error: {}\n", e)),
                    }
                });
            }
        },
        #[cfg(feature = "quickjs")]
        Some("jseval") => {
            let expr = command
                .strip_prefix("jseval")
                .unwrap_or("")
                .trim()
                .to_string();
            if expr.is_empty() {
                write_stream("EVAL_ERR:[quickjs] 用法: jseval <expression>\n".as_bytes());
            } else if !quickjs_loader::is_initialized() {
                write_stream("EVAL_ERR:[quickjs] JS 引擎未初始化，请先执行 jsinit\n".as_bytes());
            } else {
                match quickjs_loader::execute_script(&expr) {
                    Ok(result) => write_stream(format!("EVAL:{}\n", result).as_bytes()),
                    Err(e) => {
                        // 用 \r 替换 \n，避免多行错误（含堆栈）被 \n 协议分割
                        let e = e.replace('\n', "\r");
                        write_stream(format!("EVAL_ERR:{}\n", e).as_bytes());
                    }
                }
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jscomplete") => {
            let prefix = command.strip_prefix("jscomplete").unwrap_or("").trim();
            let result = quickjs_loader::complete(prefix);
            // 直接写 socket，不走 log_msg（避免 [agent] 前缀干扰 host 解析）
            write_stream(format!("COMPLETE:{}\n", result).as_bytes());
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean") => {
            quickjs_loader::cleanup();
            log_msg("[quickjs] Cleaned up\n".to_string());
        },
        // shutdown — 清理资源并退出 agent 主循环
        Some("shutdown") => {
            #[cfg(feature = "quickjs")]
            if quickjs_loader::is_initialized() {
                quickjs_loader::cleanup();
            }
            SHOULD_EXIT.store(true, Ordering::Relaxed);
        }
        _ => {
            let cmd_name = command.split_whitespace().next().unwrap_or("(empty)");
            log_msg(format!(
                "无效命令 '{}'，在 REPL 中输入 help 查看可用命令\n",
                cmd_name
            ));
        }
    }
}

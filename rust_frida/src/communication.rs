#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{bind, listen, socket, sockaddr_un, AF_UNIX, SOCK_STREAM};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use once_cell::unsync::Lazy;
use std::io::{IoSlice, Read, Write};
use std::mem::{size_of_val, zeroed};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::thread::JoinHandle;

use crate::{log_info, log_success, log_error, log_agent};

pub(crate) static AGENT_MEMFD: AtomicI32 = AtomicI32::new(-1);
pub(crate) static STOP_LISTENER: AtomicBool = AtomicBool::new(false);

/// Shared state for synchronous jscomplete request/response.
/// The Condvar is notified when the agent returns a COMPLETE: response.
static COMPLETE_RESULT: OnceLock<(Mutex<Option<Vec<String>>>, Condvar)> = OnceLock::new();

pub(crate) fn complete_state() -> &'static (Mutex<Option<Vec<String>>>, Condvar) {
    COMPLETE_RESULT.get_or_init(|| (Mutex::new(None), Condvar::new()))
}

/// Shared state for synchronous jseval request/response.
static EVAL_RESULT: OnceLock<(Mutex<Option<std::result::Result<String, String>>>, Condvar)> = OnceLock::new();

pub(crate) fn eval_state() -> &'static (Mutex<Option<std::result::Result<String, String>>>, Condvar) {
    EVAL_RESULT.get_or_init(|| (Mutex::new(None), Condvar::new()))
}

pub(crate) static GLOBAL_SENDER: OnceLock<Sender<String>> = OnceLock::new();
pub(crate) static mut AGENT_STAT: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));

pub(crate) fn send_fd_over_unix_socket(stream: &UnixStream, fd_to_send: RawFd) -> Result<(), String> {
    let data = b"AGENT_SO";
    let iov = [IoSlice::new(data)];
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let sock_fd = stream.as_raw_fd();
    sendmsg(sock_fd, &iov, &cmsg, MsgFlags::empty(), None::<&()>)
        .map_err(|e| format!("发送文件描述符失败: {}", e))?;
    Ok(())
}

pub(crate) fn handle_socket_connection(mut stream: UnixStream) {
    let mut buffer = [0; 1024];
    while let Ok(size) = stream.read(&mut buffer) {
        if size == 0 {
            break;
        }

        if let Ok(msg) = String::from_utf8(buffer[..size].to_vec()) {
            let trimmed = msg.trim();

            // 如果是 HELLO_LOADER，额外发送 memfd
            if trimmed == "HELLO_LOADER" {
                log_info!("{}", trimmed);
                let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
                if memfd >= 0 {
                    if let Err(e) = send_fd_over_unix_socket(&stream, memfd) {
                        log_error!("发送 memfd 失败: {}", e);
                    }
                } else {
                    log_error!("memfd 无效，无法发送 agent.so");
                }
            } else if trimmed == "HELLO_AGENT" {
                log_success!("Agent 已连接");
                STOP_LISTENER.store(true, Ordering::SeqCst);
                let mut stream_clone = stream.try_clone().unwrap();
                thread::spawn(move || {
                    let (sd, rx) = channel();
                    match GLOBAL_SENDER.set(sd) {
                        Ok(_) => {},
                        Err(_) => {
                            log_error!("GLOBAL_SENDER already set!");
                            return;
                        }
                    }
                    unsafe { *(AGENT_STAT.write().unwrap()) = true; }
                    while let Ok(msg) = rx.recv() {
                        match stream_clone.write_all(msg.as_bytes()) {
                            Ok(_) => {},
                            Err(e) => {
                                log_error!("stream 写入失败: {}", e);
                                break;
                            }
                        }
                    }
                });
            } else if trimmed.contains("COMPLETE:") {
                // 从消息中提取 COMPLETE: 部分（可能和其他输出混在一起）
                let complete_part = if let Some(pos) = trimmed.find("COMPLETE:") {
                    &trimmed[pos + "COMPLETE:".len()..]
                } else {
                    ""
                };
                let candidates: Vec<String> = if complete_part.is_empty() {
                    vec![]
                } else {
                    complete_part.lines().map(|s| s.to_string()).collect()
                };
                let (lock, cvar) = complete_state();
                if let Ok(mut guard) = lock.lock() {
                    *guard = Some(candidates);
                    cvar.notify_all();
                }
            } else if trimmed.contains("EVAL_ERR:") {
                let err_part = if let Some(pos) = trimmed.find("EVAL_ERR:") {
                    &trimmed[pos + "EVAL_ERR:".len()..]
                } else {
                    ""
                };
                let (lock, cvar) = eval_state();
                if let Ok(mut guard) = lock.lock() {
                    *guard = Some(Err(err_part.to_string()));
                    cvar.notify_all();
                }
            } else if trimmed.contains("EVAL:") {
                let eval_part = if let Some(pos) = trimmed.find("EVAL:") {
                    &trimmed[pos + "EVAL:".len()..]
                } else {
                    ""
                };
                let (lock, cvar) = eval_state();
                if let Ok(mut guard) = lock.lock() {
                    *guard = Some(Ok(eval_part.to_string()));
                    cvar.notify_all();
                }
            } else {
                log_agent!("{}", trimmed);
            }
        }
    }
}

pub(crate) fn start_socket_listener(socket_path: &str) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
    // 创建 socket
    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 构造 sockaddr_un，抽象socket: sun_path[0]=0, 后面跟名字
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    let name_bytes = socket_path.as_bytes();
    let path_len = name_bytes.len().min(107); // sun_path最多108字节
    addr.sun_path[0] = 0; // 抽象socket
    addr.sun_path[1..=path_len].copy_from_slice(&name_bytes[..path_len]);
    let sockaddr_len = (size_of_val(&addr.sun_family) + 1 + path_len) as u32;

    // 绑定
    let ret = unsafe {
        bind(
            fd,
            &addr as *const _ as *const _,
            sockaddr_len,
        )
    };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 监听
    let ret = unsafe { listen(fd, 128) };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 转为 Rust 的 UnixListener，设为非阻塞以便响应停止信号
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    listener.set_nonblocking(true).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    let handle = thread::spawn(move || {
        loop {
            if STOP_LISTENER.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    thread::spawn(move || {
                        handle_socket_connection(stream);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => log_error!("接受连接失败: {}", e),
            }
        }
    });
    Ok(handle)
}

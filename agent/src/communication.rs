//! agent 端 socket 通信模块

use libc::{c_char, close, sockaddr, sockaddr_un, AF_UNIX};
use std::io::{Error, Write};
use std::mem::{size_of, zeroed};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

/// 动态 socket 名，由 hello_entry() 从 StringTable 读取后保存
pub(crate) static SOCKET_NAME: OnceLock<String> = OnceLock::new();

pub(crate) fn connect_socket() -> Result<UnixStream, String> {
    // 优先使用 hello_entry() 从 StringTable 读取的动态 socket 名（rust_frida_{pid}），
    // 回退到旧的硬编码值（仅用于兼容老版本 host）
    let name_str = SOCKET_NAME
        .get()
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| b"rust_frida_socket".to_vec());
    let name = name_str.as_slice();
    let fd = unsafe { libc::socket(AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("创建 socket 失败: {}", Error::last_os_error()));
    }

    // 构造 abstract sockaddr_un
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    addr.sun_path[0] = 0; // abstract namespace
    for (i, &b) in name.iter().enumerate() {
        addr.sun_path[i + 1] = b as c_char;
    }

    // 计算 sockaddr_un 长度
    let addr_len = (size_of::<libc::sa_family_t>() + 1 + name.len()) as u32;

    // 连接
    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const sockaddr,
            addr_len,
        )
    };
    if ret != 0 {
        let err = Error::last_os_error();
        unsafe { close(fd) };
        return Err(format!("连接到套接字失败: {}", err));
    }

    // 用 Rust 的 UnixStream 包装 fd，方便写数据
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    Ok(stream)
}

/// Write-half of the agent↔host socket, protected by Mutex to serialize messages
pub static GLOBAL_STREAM: OnceLock<Mutex<UnixStream>> = OnceLock::new();

/// Write `data` to the global socket stream, serialized via Mutex.
pub(crate) fn write_stream(data: &[u8]) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = m.lock().unwrap_or_else(|e| e.into_inner()).write_all(data);
    }
}

pub(crate) static CACHE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// 日志函数：socket未连接时缓存，已连接时直接发送
/// 自动添加 [agent] 前缀
pub(crate) fn log_msg(msg: String) {
    let prefixed = format!("[agent] {}", msg);
    if GLOBAL_STREAM.get().is_some() {
        write_stream(prefixed.as_bytes());
    } else {
        // Socket未连接，缓存日志
        if let Ok(mut cache) = CACHE_LOG.lock() {
            cache.push(prefixed);
        }
    }
}

/// 刷新缓存的日志，在socket连接后调用
pub(crate) fn flush_cached_logs() {
    if GLOBAL_STREAM.get().is_some() {
        if let Ok(mut cache) = CACHE_LOG.lock() {
            for msg in cache.drain(..) {
                write_stream(msg.as_bytes());
            }
        }
    }
}

#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use clap::Parser;

fn parse_pid(s: &str) -> std::result::Result<i32, String> {
    match s.parse::<i32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("PID 必须是正整数".to_string()),
    }
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    /// 目标进程的PID（与 --watch-so 互斥）
    #[arg(
        short,
        long,
        required_unless_present = "watch_so",
        conflicts_with = "watch_so",
        allow_hyphen_values = true,
        value_parser = parse_pid
    )]
    pub(crate) pid: Option<i32>,

    /// 监听指定 SO 路径加载，自动附加到加载该 SO 的进程
    #[arg(short = 'w', long = "watch-so")]
    pub(crate) watch_so: Option<String>,

    /// 监听超时时间（秒），默认无限等待
    #[arg(short = 't', long = "timeout")]
    pub(crate) timeout: Option<u64>,

    /// 添加自定义字符串到字符串表（可多次使用）
    /// 格式: name=value 或直接指定值
    #[arg(short = 's', long = "string", value_name = "NAME=VALUE")]
    pub(crate) strings: Vec<String>,

    /// 加载并执行JavaScript脚本文件
    #[arg(short = 'l', long = "load-script", value_name = "FILE")]
    pub(crate) load_script: Option<String>,

    /// 显示详细注入信息（地址、偏移等）
    #[arg(short = 'v', long = "verbose")]
    pub(crate) verbose: bool,
}

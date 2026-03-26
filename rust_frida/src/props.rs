#![cfg(all(target_os = "android", target_arch = "aarch64"))]

//! 属性覆盖伪装模块：dump 本机属性 → 定制修改 → zymbiote 自动 mount+remap
//!
//! 工作流程:
//! 1. `--dump-props <profile>`: 复制 /dev/__properties__/ 到 profile 目录 + getprop 输出
//! 2. 用户编辑 profile 目录下的 override.prop (key=value 格式)
//! 3. `--spawn <pkg> --profile <profile>`: 预处理(patch 文件) → zymbiote 在 fork 后自动 mount+remap

use std::collections::HashMap;

use crate::{log_info, log_step, log_success, log_verbose, log_warn};

/// 属性 profile 存储目录（放在 /dev/__properties__/ 下，app 可读）
pub(crate) const PROP_PROFILES_DIR: &str = "/dev/__properties__/.profiles";
/// 系统属性区域目录
const PROP_SRC_DIR: &str = "/dev/__properties__";
/// prop_area magic: "PROP" in LE
const PROP_AREA_MAGIC: u32 = 0x504f5250;
/// prop_area header 大小
const PROP_AREA_HEADER_SIZE: usize = 128;
/// prop_info value 字段大小 (PROP_VALUE_MAX)
const PROP_VALUE_MAX: usize = 92;

// ─── 公开 API ────────────────────────────────────────────────────────────────

/// Dump 本机属性到 profile
pub(crate) fn dump_props(profile_name: &str) -> Result<(), String> {
    let profile_dir = format!("{}/{}", PROP_PROFILES_DIR, profile_name);

    log_step!("Dump 属性到 profile: {}", profile_name);

    // 创建 profile 目录
    std::fs::create_dir_all(&profile_dir)
        .map_err(|e| format!("创建目录 {} 失败: {}", profile_dir, e))?;

    // 复制 /dev/__properties__/ 下所有文件
    let entries = std::fs::read_dir(PROP_SRC_DIR)
        .map_err(|e| format!("读取 {} 失败: {}", PROP_SRC_DIR, e))?;

    let mut count = 0u32;
    for entry in entries {
        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let src = entry.path();
        if !src.is_file() {
            continue;
        }

        let filename = entry.file_name();
        let dst = format!("{}/{}", profile_dir, filename.to_string_lossy());

        std::fs::copy(&src, &dst)
            .map_err(|e| format!("复制 {:?} → {} 失败: {}", src, dst, e))?;
        count += 1;
    }
    log_info!("已复制 {} 个属性区域文件", count);

    // Dump getprop 输出（人类可读参考）
    let output = std::process::Command::new("getprop")
        .output()
        .map_err(|e| format!("执行 getprop 失败: {}", e))?;

    let props_path = format!("{}/props.txt", profile_dir);
    std::fs::write(&props_path, &output.stdout)
        .map_err(|e| format!("写入 {} 失败: {}", props_path, e))?;

    // 创建 override.prop 模板（仅首次）
    let override_path = format!("{}/override.prop", profile_dir);
    if !std::path::Path::new(&override_path).exists() {
        let template = "\
# 属性覆盖文件 — 每行格式: key=value
# 注释行以 # 开头，空行忽略
#
# 示例:
# ro.build.fingerprint=google/oriole/oriole:12/SQ3A.220705.003.A1/8672226:user/release-keys
# ro.build.display.id=SQ3A.220705.003.A1
# ro.debuggable=0
# ro.secure=1
# ro.build.tags=release-keys
# ro.build.type=user
";
        std::fs::write(&override_path, template)
            .map_err(|e| format!("写入 {} 失败: {}", override_path, e))?;
    }

    log_success!("Profile '{}' 已保存到 {}", profile_name, profile_dir);
    log_info!("  props.txt      — getprop 完整输出 (参考)");
    log_info!("  override.prop  — 编辑此文件定义属性覆盖");
    log_info!("  其他文件       — 原始属性区域二进制文件");
    log_info!("");
    log_info!(
        "使用方法: rustfrida --spawn <package> --profile {}",
        profile_name
    );

    Ok(())
}

/// 列出已有 profile
#[allow(dead_code)]
pub(crate) fn list_profiles() -> Vec<String> {
    let mut profiles = Vec::new();
    if let Ok(entries) = std::fs::read_dir(PROP_PROFILES_DIR) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    profiles.push(name.to_string());
                }
            }
        }
    }
    profiles
}

/// 预处理属性 profile：patch 文件 + 返回 profile 目录路径
///
/// 在 spawn_and_inject 之前调用。patch 完成后，zymbiote 在 fork 的子进程中
/// 自动 mount bind + remap，无需 ptrace。
pub(crate) fn prep_prop_profile(profile_name: &str) -> Result<String, String> {
    let profile_dir = format!("{}/{}", PROP_PROFILES_DIR, profile_name);

    if !std::path::Path::new(&profile_dir).exists() {
        return Err(format!(
            "Profile '{}' 不存在 (路径: {})\n  先运行: rustfrida --dump-props {}",
            profile_name, profile_dir, profile_name
        ));
    }

    log_step!("预处理属性 profile: {}", profile_name);

    // 读取 override.prop
    let override_path = format!("{}/override.prop", profile_dir);
    let overrides = if std::path::Path::new(&override_path).exists() {
        parse_override_file(&override_path)?
    } else {
        HashMap::new()
    };

    if overrides.is_empty() {
        log_info!("override.prop 为空，使用 dump 时的属性快照");
    } else {
        log_info!("属性覆盖 ({} 条):", overrides.len());
        for (k, v) in &overrides {
            println!("     {} = {}", k, v);
        }

        // 修补 profile 中的属性文件
        let count = patch_prop_files(&profile_dir, &overrides)?;
        log_success!("已修补 {} 个属性文件", count);
    }

    // 写 .active 文件：zymbiote 读取此文件获取 profile 目录路径
    let active_path = format!("{}/.active", PROP_PROFILES_DIR);
    std::fs::write(&active_path, format!("{}\n", profile_dir))
        .map_err(|e| format!("写入 {} 失败: {}", active_path, e))?;

    log_info!(
        "Profile '{}' 已就绪，zymbiote 将在子进程 fork 后自动 mount+remap",
        profile_name
    );

    Ok(profile_dir)
}

// ─── 内部实现 ────────────────────────────────────────────────────────────────

/// 解析 override.prop 文件 → HashMap<key, value>
fn parse_override_file(path: &str) -> Result<HashMap<String, String>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败: {}", path, e))?;

    let mut overrides = HashMap::new();
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                log_warn!("override.prop:{}: 空 key，跳过", lineno + 1);
                continue;
            }
            if value.len() >= PROP_VALUE_MAX {
                log_warn!(
                    "override.prop:{}: 值超过 {} 字节限制: {}",
                    lineno + 1,
                    PROP_VALUE_MAX - 1,
                    key
                );
                continue;
            }
            overrides.insert(key.to_string(), value.to_string());
        } else {
            log_warn!(
                "override.prop:{}: 格式错误 (应为 key=value): {}",
                lineno + 1,
                line
            );
        }
    }

    Ok(overrides)
}

/// 修补 profile 中的属性区域文件
///
/// 在每个 prop_area 文件中搜索目标属性名，找到后覆写 value 字段。
/// prop_info 内存布局: serial(4) + value(PROP_VALUE_MAX=92) + name(null-terminated)
/// 返回成功修补的属性数量。
fn patch_prop_files(
    profile_dir: &str,
    overrides: &HashMap<String, String>,
) -> Result<usize, String> {
    if overrides.is_empty() {
        return Ok(0);
    }

    let mut patch_count = 0usize;
    let mut remaining: HashMap<&str, &str> = overrides
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let entries = std::fs::read_dir(profile_dir)
        .map_err(|e| format!("读取 {} 失败: {}", profile_dir, e))?;

    for entry in entries {
        if remaining.is_empty() {
            break;
        }

        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let filename = entry.file_name().to_string_lossy().to_string();
        // 跳过非属性区域文件
        if matches!(
            filename.as_str(),
            "props.txt" | "override.prop" | "properties_serial"
        ) {
            continue;
        }

        let mut data =
            std::fs::read(&path).map_err(|e| format!("读取 {:?} 失败: {}", path, e))?;

        // 验证 prop_area magic
        if data.len() < PROP_AREA_HEADER_SIZE {
            continue;
        }
        let magic = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if magic != PROP_AREA_MAGIC {
            continue;
        }

        let mut modified = false;

        // 在当前文件中搜索每个待覆盖的属性
        let keys: Vec<String> = remaining.keys().map(|k| k.to_string()).collect();
        for key in &keys {
            let new_value = remaining[key.as_str()];

            // 构造 null-terminated 搜索模式（全名匹配，不会误命中 trie 节点的片段）
            let mut search = key.as_bytes().to_vec();
            search.push(0);

            if let Some(rel_offset) = find_bytes(&data[PROP_AREA_HEADER_SIZE..], &search) {
                let name_offset = PROP_AREA_HEADER_SIZE + rel_offset;

                // prop_info: serial(4) + value(92) + name
                if name_offset < PROP_VALUE_MAX + 4 {
                    log_warn!("属性 {} 偏移异常 (offset={}), 跳过", key, name_offset);
                    continue;
                }

                let value_offset = name_offset - PROP_VALUE_MAX;
                let serial_offset = value_offset - 4;

                // 读取 serial 判断是否为 long property
                let serial = u32::from_le_bytes(
                    data[serial_offset..serial_offset + 4].try_into().unwrap(),
                );
                // long property 标记: value 区域包含 "Must use __system_property_read_callback"
                let is_long = data[value_offset..value_offset + 10]
                    .starts_with(b"Must use _");

                // 读取旧值
                let old_value = if is_long {
                    // long property: 实际值在 name 之后
                    let long_start = name_offset + key.len() + 1; // name\0 之后
                    // 对齐到 4 字节
                    let long_start = (long_start + 3) & !3;
                    if long_start < data.len() {
                        let end = data[long_start..].iter()
                            .position(|&b| b == 0)
                            .unwrap_or(0);
                        String::from_utf8_lossy(&data[long_start..long_start + end]).to_string()
                    } else {
                        String::new()
                    }
                } else {
                    let old_end = data[value_offset..name_offset]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(PROP_VALUE_MAX);
                    String::from_utf8_lossy(&data[value_offset..value_offset + old_end])
                        .to_string()
                };

                // 写入新值: 清零 value 区域 + 写入短值 + 重置 serial 为 short property
                for byte in data[value_offset..value_offset + PROP_VALUE_MAX].iter_mut() {
                    *byte = 0;
                }
                let new_bytes = new_value.as_bytes();
                data[value_offset..value_offset + new_bytes.len()].copy_from_slice(new_bytes);

                // 设置 serial 为 short property 格式（清除 long property 标记）
                // serial 格式: 偶数=stable, 低位=0 表示非 long
                let new_serial = 2u32; // 最简单的 valid short serial
                data[serial_offset..serial_offset + 4]
                    .copy_from_slice(&new_serial.to_le_bytes());

                log_verbose!(
                    "修补属性 [{}] 在 {} (offset=0x{:x}): '{}' → '{}'",
                    key,
                    filename,
                    value_offset,
                    old_value,
                    new_value
                );

                patch_count += 1;
                modified = true;
                remaining.remove(key.as_str());
            }
        }

        if modified {
            std::fs::write(&path, &data)
                .map_err(|e| format!("写回 {:?} 失败: {}", path, e))?;
        }
    }

    // 报告未找到的属性
    for key in remaining.keys() {
        log_warn!("未在属性文件中找到: {} (可能是运行时动态设置的属性)", key);
    }

    Ok(patch_count)
}

/// 在 haystack 中搜索 needle，返回首次匹配的起始偏移
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

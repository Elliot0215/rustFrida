//! ArtMethod resolution, entry_point access, ART bridge function discovery, field cache
//!
//! Contains: resolve_art_method, read_entry_point, find_art_bridge_functions,
//! ArtBridgeFunctions, CachedFieldInfo, FIELD_CACHE, cache_fields_for_class.

use crate::jsapi::console::output_message;
use crate::jsapi::module::{libart_dlsym, dlsym_first_match, is_in_libart};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

use super::jni_core::*;
use super::reflect::*;

// ============================================================================
// ART bridge functions — ART internal trampoline addresses
// ============================================================================

/// ART 内部桥接函数地址集合
/// 当前仅使用 quick_generic_jni_trampoline，其余保留以备后用
#[allow(dead_code)]
pub(super) struct ArtBridgeFunctions {
    /// art_quick_generic_jni_trampoline — JNI native method 分发入口
    pub(super) quick_generic_jni_trampoline: u64,
    /// art_quick_to_interpreter_bridge — 编译代码到解释器的桥接
    pub(super) quick_to_interpreter_bridge: u64,
    /// art_quick_resolution_trampoline — 方法解析 trampoline
    pub(super) quick_resolution_trampoline: u64,
    /// Nterp 解释器入口点（Android 12+），0 表示不可用
    pub(super) nterp_entry_point: u64,
    /// art::interpreter::DoCall<> 模板实例地址（最多4个）
    pub(super) do_call_addrs: Vec<u64>,
    /// GC 同步: ConcurrentCopying::CopyingPhase 地址，0 表示不可用
    pub(super) gc_copying_phase: u64,
    /// GC 同步: Heap::CollectGarbageInternal 地址，0 表示不可用
    pub(super) gc_collect_internal: u64,
    /// GC 同步: Thread::RunFlipFunction 地址，0 表示不可用
    pub(super) run_flip_function: u64,
    /// ArtMethod::GetOatQuickMethodHeader 地址，0 表示不可用
    pub(super) get_oat_quick_method_header: u64,
    /// ClassLinker::FixupStaticTrampolines / MakeInitializedClassesVisiblyInitialized 地址，0 表示不可用
    pub(super) fixup_static_trampolines: u64,
}

unsafe impl Send for ArtBridgeFunctions {}
unsafe impl Sync for ArtBridgeFunctions {}

/// 全局缓存的 ART bridge 函数地址
pub(super) static ART_BRIDGE_FUNCTIONS: std::sync::OnceLock<ArtBridgeFunctions> = std::sync::OnceLock::new();

/// 发现并缓存所有 ART 内部桥接函数地址。
///
/// 策略:
/// 1. ClassLinker 扫描: 一次扫描提取 quick_generic_jni_trampoline、
///    quick_to_interpreter_bridge、quick_resolution_trampoline
/// 2. dlsym: GetNterpEntryPoint（调用它获取 nterp 入口）、DoCall 模板实例、
///    ConcurrentCopying::CopyingPhase
pub(super) unsafe fn find_art_bridge_functions(env: JniEnv, _ep_offset: usize) -> &'static ArtBridgeFunctions {
    ART_BRIDGE_FUNCTIONS.get_or_init(|| {
        output_message("[art bridge] 开始发现 ART 内部桥接函数...");

        // --- ClassLinker 扫描: 一次提取 3 个 trampoline ---
        let (jni_tramp, interp_bridge, resolution_tramp) = find_classlinker_trampolines(env);

        output_message(&format!(
            "[art bridge] ClassLinker 结果: jni_tramp={:#x}, interp_bridge={:#x}, resolution_tramp={:#x}",
            jni_tramp, interp_bridge, resolution_tramp
        ));

        // --- dlsym: Nterp 入口点 ---
        let nterp = find_nterp_entry_point();
        output_message(&format!("[art bridge] nterp_entry_point={:#x}", nterp));

        // --- dlsym: DoCall 模板实例 ---
        let do_calls = find_do_call_symbols();
        output_message(&format!("[art bridge] DoCall 实例数={}", do_calls.len()));
        for (i, addr) in do_calls.iter().enumerate() {
            output_message(&format!("[art bridge]   DoCall[{}]={:#x}", i, addr));
        }

        // --- dlsym: GC ConcurrentCopying::CopyingPhase ---
        let gc_phase = find_gc_copying_phase();
        output_message(&format!("[art bridge] gc_copying_phase={:#x}", gc_phase));

        // --- dlsym: Heap::CollectGarbageInternal ---
        let gc_collect = find_gc_collect_internal();
        output_message(&format!("[art bridge] gc_collect_internal={:#x}", gc_collect));

        // --- dlsym: Thread::RunFlipFunction ---
        let run_flip = find_run_flip_function();
        output_message(&format!("[art bridge] run_flip_function={:#x}", run_flip));

        // --- dlsym: ArtMethod::GetOatQuickMethodHeader ---
        let get_oat_header = find_get_oat_quick_method_header();
        output_message(&format!("[art bridge] get_oat_quick_method_header={:#x}", get_oat_header));

        // --- dlsym: FixupStaticTrampolines / MakeInitializedClassesVisiblyInitialized ---
        let fixup_static = find_fixup_static_trampolines();
        output_message(&format!("[art bridge] fixup_static_trampolines={:#x}", fixup_static));

        output_message("[art bridge] ART 桥接函数发现完成");

        ArtBridgeFunctions {
            quick_generic_jni_trampoline: jni_tramp,
            quick_to_interpreter_bridge: interp_bridge,
            quick_resolution_trampoline: resolution_tramp,
            nterp_entry_point: nterp,
            do_call_addrs: do_calls,
            gc_copying_phase: gc_phase,
            gc_collect_internal: gc_collect,
            run_flip_function: run_flip,
            get_oat_quick_method_header: get_oat_header,
            fixup_static_trampolines: fixup_static,
        }
    })
}

/// 通过 ClassLinker 结构体扫描提取 3 个 ART trampoline 地址。
///
/// ClassLinker 布局 (Android 6+, 以 intern_table_ 为锚点):
///   intern_table_
///   quick_resolution_trampoline_            +1*8
///   quick_imt_conflict_trampoline_          +2*8
///   ... (delta 变量取决于 API 级别)
///   quick_generic_jni_trampoline_           +(delta)*8
///   quick_to_interpreter_bridge_trampoline_ +(delta+1)*8
///
/// 返回 (quick_generic_jni_trampoline, quick_to_interpreter_bridge, quick_resolution_trampoline)
unsafe fn find_classlinker_trampolines(_env: JniEnv) -> (u64, u64, u64) {
    // --- Strategy 1: dlsym (可能在某些 Android 构建中可用) ---
    // 注意: art_quick_* 符号通常是 LOCAL HIDDEN，dlsym 一般找不到
    let sym_jni = CString::new("art_quick_generic_jni_trampoline").unwrap();
    let sym_interp = CString::new("art_quick_to_interpreter_bridge").unwrap();
    let sym_resolution = CString::new("art_quick_resolution_trampoline").unwrap();

    let jni_sym = libc::dlsym(libc::RTLD_DEFAULT, sym_jni.as_ptr());
    let interp_sym = libc::dlsym(libc::RTLD_DEFAULT, sym_interp.as_ptr());
    let resolution_sym = libc::dlsym(libc::RTLD_DEFAULT, sym_resolution.as_ptr());

    if !jni_sym.is_null() && !interp_sym.is_null() && !resolution_sym.is_null() {
        output_message("[art bridge] 全部通过 dlsym 发现");
        return (jni_sym as u64, interp_sym as u64, resolution_sym as u64);
    }

    // --- Strategy 2: ClassLinker 扫描 (主要策略) ---
    // art_quick_* 是 LOCAL HIDDEN 符号，APEX namespace 限制下 dlsym 找不到
    // 必须通过 ClassLinker 结构体内存扫描获取
    output_message("[art bridge] dlsym 未能获取全部地址，尝试 ClassLinker 扫描...");

    let vm_ptr = {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(state) => state.vm,
            None => {
                output_message("[art bridge] ClassLinker 扫描: 无 JavaVM 缓存");
                return (jni_sym as u64, interp_sym as u64, resolution_sym as u64);
            }
        }
    };

    // JavaVMExt.runtime_ 在 offset 8（vtable 指针之后）
    let runtime_raw = *((vm_ptr as usize + 8) as *const u64);
    let runtime = runtime_raw & 0x00FF_FFFF_FFFF_FFFF;
    if runtime == 0 {
        output_message(&format!(
            "[art bridge] ClassLinker 扫描: runtime 指针为空 (raw={:#x})", runtime_raw
        ));
        return (jni_sym as u64, interp_sym as u64, resolution_sym as u64);
    }

    output_message(&format!(
        "[art bridge] JavaVM={:#x}, Runtime={:#x}", vm_ptr as u64, runtime
    ));

    // 扫描 Runtime 查找 java_vm_ 字段
    let vm_addr_stripped = (vm_ptr as u64) & 0x00FF_FFFF_FFFF_FFFF;
    let scan_start = 384usize;
    let scan_end = scan_start + 800;

    let mut java_vm_offset: Option<usize> = None;
    for offset in (scan_start..scan_end).step_by(8) {
        let val = *((runtime as usize + offset) as *const u64);
        let val_stripped = val & 0x00FF_FFFF_FFFF_FFFF;
        if val_stripped == vm_addr_stripped {
            java_vm_offset = Some(offset);
            output_message(&format!(
                "[art bridge] 找到 java_vm_ 在 Runtime+{:#x}", offset
            ));
            break;
        }
    }

    let java_vm_off = match java_vm_offset {
        Some(o) => o,
        None => {
            output_message("[art bridge] ClassLinker 扫描: Runtime 中未找到 java_vm_");
            return (jni_sym as u64, interp_sym as u64, resolution_sym as u64);
        }
    };

    let api_level = get_android_api_level();
    output_message(&format!("[art bridge] Android API 级别: {}", api_level));

    // 根据 API 级别确定 classLinker_ 在 Runtime 中的候选偏移
    let class_linker_candidates: Vec<usize> = if api_level >= 33 {
        vec![java_vm_off - 4 * 8]
    } else if api_level >= 30 {
        vec![java_vm_off - 3 * 8, java_vm_off - 4 * 8]
    } else if api_level >= 29 {
        vec![java_vm_off - 2 * 8]
    } else {
        vec![java_vm_off - 3 * 8 - 3 * 8]
    };

    for &cl_off in &class_linker_candidates {
        let class_linker_raw = *((runtime as usize + cl_off) as *const u64);
        let class_linker = class_linker_raw & 0x00FF_FFFF_FFFF_FFFF;
        if class_linker == 0 {
            continue;
        }

        let intern_table_off = cl_off - 8;
        let intern_table_raw = *((runtime as usize + intern_table_off) as *const u64);
        let intern_table = intern_table_raw & 0x00FF_FFFF_FFFF_FFFF;
        if intern_table == 0 {
            continue;
        }

        output_message(&format!(
            "[art bridge] 候选: classLinker={:#x} (Runtime+{:#x}), internTable={:#x} (Runtime+{:#x})",
            class_linker, cl_off, intern_table, intern_table_off
        ));

        // 在 ClassLinker 中扫描 intern_table_ 指针作为锚点
        let cl_scan_start = 200usize;
        let cl_scan_end = cl_scan_start + 800;

        let mut intern_table_cl_offset: Option<usize> = None;
        for offset in (cl_scan_start..cl_scan_end).step_by(8) {
            let val = *((class_linker as usize + offset) as *const u64);
            let val_stripped = val & 0x00FF_FFFF_FFFF_FFFF;
            if val_stripped == intern_table {
                intern_table_cl_offset = Some(offset);
                output_message(&format!(
                    "[art bridge] 找到 intern_table_ 在 ClassLinker+{:#x}", offset
                ));
                break;
            }
        }

        let it_off = match intern_table_cl_offset {
            Some(o) => o,
            None => {
                output_message("[art bridge] 此候选 ClassLinker 中未找到 intern_table_");
                continue;
            }
        };

        // 根据 API 级别计算 delta
        let delta: usize = if api_level >= 30 {
            6
        } else if api_level >= 29 {
            4
        } else {
            3
        };

        // 提取三个 trampoline 地址
        let jni_tramp_off = it_off + delta * 8;
        let interp_bridge_off = jni_tramp_off + 8;
        // resolution trampoline 在 intern_table_ 之后第一个位置
        let resolution_tramp_off = it_off + 1 * 8;

        let jni_tramp_addr = *((class_linker as usize + jni_tramp_off) as *const u64);
        let jni_tramp = jni_tramp_addr & 0x0000_FFFF_FFFF_FFFF; // strip PAC

        let interp_bridge_addr = *((class_linker as usize + interp_bridge_off) as *const u64);
        let interp_bridge = interp_bridge_addr & 0x0000_FFFF_FFFF_FFFF;

        let resolution_tramp_addr = *((class_linker as usize + resolution_tramp_off) as *const u64);
        let resolution_tramp = resolution_tramp_addr & 0x0000_FFFF_FFFF_FFFF;

        output_message(&format!(
            "[art bridge] ClassLinker: jni_tramp=ClassLinker+{:#x}={:#x}, interp=ClassLinker+{:#x}={:#x}, resolution=ClassLinker+{:#x}={:#x}",
            jni_tramp_off, jni_tramp, interp_bridge_off, interp_bridge, resolution_tramp_off, resolution_tramp
        ));

        // 验证: 应为 libart.so 中的代码指针
        if jni_tramp != 0 && is_code_pointer(jni_tramp) {
            // 对可能通过 dlsym 找到的地址使用 dlsym 值，否则用 ClassLinker 值
            let final_jni = if jni_sym.is_null() { jni_tramp } else { jni_sym as u64 };
            let final_interp = if interp_bridge != 0 && is_code_pointer(interp_bridge) {
                interp_bridge
            } else if !interp_sym.is_null() {
                interp_sym as u64
            } else {
                0
            };
            let final_resolution = if resolution_tramp != 0 && is_code_pointer(resolution_tramp) {
                resolution_tramp
            } else if !resolution_sym.is_null() {
                resolution_sym as u64
            } else {
                0
            };

            return (final_jni, final_interp, final_resolution);
        }
    }

    output_message("[art bridge] ClassLinker 扫描失败，返回 dlsym 结果（部分可能为0）");
    (jni_sym as u64, interp_sym as u64, resolution_sym as u64)
}

/// 查找 Nterp 解释器入口点（Android 12+ / API 31+）
///
/// 策略 1: dlsym("art::interpreter::GetNterpEntryPoint") → 调用它获取入口点
/// 策略 2: dlsym("ExecuteNterpImpl") — 直接查找（通常 LOCAL HIDDEN，可能失败）
/// 返回 0 表示不可用（Android 11 及以下无 Nterp）
unsafe fn find_nterp_entry_point() -> u64 {
    // 策略 1: GetNterpEntryPoint 是一个返回入口点地址的函数
    let func_ptr = libart_dlsym("_ZN3art11interpreter18GetNterpEntryPointEv");
    if !func_ptr.is_null() {
        let get_nterp: unsafe extern "C" fn() -> u64 = std::mem::transmute(func_ptr);
        let ep = get_nterp();
        if ep != 0 {
            output_message(&format!(
                "[art bridge] Nterp 入口点通过 GetNterpEntryPoint() 获取: {:#x}", ep
            ));
            return ep;
        }
    }

    // 策略 2: ExecuteNterpImpl（LOCAL HIDDEN，通常无法通过 dlsym 访问）
    let func_ptr2 = libart_dlsym("ExecuteNterpImpl");
    if !func_ptr2.is_null() {
        output_message(&format!(
            "[art bridge] Nterp 入口点通过 ExecuteNterpImpl 获取: {:#x}", func_ptr2 as u64
        ));
        return func_ptr2 as u64;
    }

    output_message("[art bridge] Nterp 入口点不可用（Android 11 及以下）");
    0
}

/// 查找 art::interpreter::DoCall<> 模板实例（4个：bool×bool 组合）
///
/// Android 12 (API 23-33) 使用:
///   _ZN3art11interpreter6DoCallILb{0,1}ELb{0,1}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE
unsafe fn find_do_call_symbols() -> Vec<u64> {
    let api_level = get_android_api_level();

    // 根据 API 级别构建符号名模式
    let symbols: Vec<String> = if api_level <= 22 {
        // Android 5.x: ArtMethod 在 mirror 命名空间
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            for b1 in &["0", "1"] {
                syms.push(format!(
                    "_ZN3art11interpreter6DoCallILb{}ELb{}EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE",
                    b0, b1
                ));
            }
        }
        syms
    } else if api_level <= 33 {
        // Android 6-13: 标准签名
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            for b1 in &["0", "1"] {
                syms.push(format!(
                    "_ZN3art11interpreter6DoCallILb{}ELb{}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE",
                    b0, b1
                ));
            }
        }
        syms
    } else {
        // Android 14+: 单 bool 模板参数
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            syms.push(format!(
                "_ZN3art11interpreter6DoCallILb{}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE",
                b0
            ));
        }
        syms
    };

    let mut addrs = Vec::new();
    for sym_str in &symbols {
        let addr = libart_dlsym(sym_str);
        if !addr.is_null() {
            addrs.push(addr as u64);
        }
    }

    addrs
}

/// 清空 JIT 代码缓存: 调用 JitCodeCache::InvalidateAllMethods()
///
/// 首次 hook 时调用一次，使所有已 JIT 编译的代码失效:
/// - 已内联被 hook 方法的调用者代码失效 → 退回解释器
/// - 重新 JIT 时不再内联被 hook 方法 (kAccSingleImplementation 已清除)
///
/// best-effort: 符号未找到或指针无效时仅 log 警告，不阻断 hook 流程。
pub(super) unsafe fn try_invalidate_jit_cache() {
    // 查找 InvalidateAllMethods 符号
    let func_ptr = libart_dlsym("_ZN3art3jit12JitCodeCache21InvalidateAllMethodsEv");

    if func_ptr.is_null() {
        output_message("[jit cache] InvalidateAllMethods 符号未找到，跳过 JIT 缓存清空");
        return;
    }

    // 从 JavaVM → Runtime → jit_code_cache_ 导航获取 JitCodeCache*
    let vm_ptr = {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(state) => state.vm,
            None => {
                output_message("[jit cache] 无 JavaVM 缓存，跳过 JIT 缓存清空");
                return;
            }
        }
    };

    // JavaVMExt.runtime_ 在 offset 8 (vtable 之后)
    let runtime_raw = *((vm_ptr as usize + 8) as *const u64);
    let runtime = runtime_raw & 0x00FF_FFFF_FFFF_FFFF;
    if runtime == 0 {
        output_message("[jit cache] Runtime 指针为空，跳过 JIT 缓存清空");
        return;
    }

    // 从 Runtime 获取 jit_code_cache_:
    // 尝试 dlsym Runtime::instance_ 获取更可靠的路径
    let instance_sym = CString::new("_ZN3art7Runtime9instance_E").unwrap();
    let instance_ptr = libc::dlsym(libc::RTLD_DEFAULT, instance_sym.as_ptr());

    let runtime_addr = if !instance_ptr.is_null() {
        let rt = *(instance_ptr as *const u64);
        let rt_stripped = rt & 0x00FF_FFFF_FFFF_FFFF;
        if rt_stripped != 0 { rt_stripped } else { runtime }
    } else {
        runtime
    };

    // 扫描 Runtime 查找 jit_ (Jit*) 指针
    // jit_ 通常在 Runtime 布局的后半部分
    // 策略: 通过 dlsym 查找 Jit::code_cache_ 的偏移
    // 简化方案: 直接用 dlsym 查找 jit_code_cache_ 全局或从 Runtime 扫描

    // 方案 A: 尝试 Runtime::jit_code_cache_ 直接访问
    // Runtime 的 jit_code_cache_ 字段可以通过扫描找到
    // 但更可靠的方式是: 扫描 Runtime 找到 Jit* (非空且是合理的堆指针)
    // 然后从 Jit 中取 code_cache_ (通常在 Jit+8 或 Jit+16)

    // 方案 B (更简单): 通过 dlsym 获取 jit_code_cache_ 成员偏移
    // 实际上最简单的方案: 扫描 Runtime 寻找指向合法 JitCodeCache 的指针

    // 使用 Jit::GetCodeCache() 如果可用
    let get_code_cache_sym = CString::new(
        "_ZNK3art3jit3Jit12GetCodeCacheEv"
    ).unwrap();
    let get_code_cache_ptr = libc::dlsym(libc::RTLD_DEFAULT, get_code_cache_sym.as_ptr());

    if !get_code_cache_ptr.is_null() {
        // 需要 Jit* this — 从 Runtime 获取
        // Runtime::jit_ 指针扫描
        // jit_ 通常在 Runtime 中较后的位置 (offset 600-900)
        let scan_start = 500usize;
        let scan_end = 1200usize;

        for offset in (scan_start..scan_end).step_by(8) {
            let candidate = *((runtime_addr as usize + offset) as *const u64);
            let candidate_stripped = candidate & 0x00FF_FFFF_FFFF_FFFF;

            // 跳过空指针和非堆地址
            if candidate_stripped == 0 || candidate_stripped < 0x7000_0000 {
                continue;
            }

            // 尝试作为 Jit* 调用 GetCodeCache()
            // GetCodeCache 是 const 方法: JitCodeCache* GetCodeCache() const
            type GetCodeCacheFn = unsafe extern "C" fn(this: u64) -> u64;
            let get_code_cache: GetCodeCacheFn = std::mem::transmute(get_code_cache_ptr);

            // 安全检查: 确保 candidate 看起来像合理的对象指针
            // 读取前 8 字节看是否为合理值
            let first_word = *((candidate_stripped as usize) as *const u64);
            if first_word == 0 {
                continue;
            }

            let code_cache = get_code_cache(candidate_stripped);
            let code_cache_stripped = code_cache & 0x00FF_FFFF_FFFF_FFFF;
            if code_cache_stripped != 0 && code_cache_stripped > 0x7000_0000 {
                // 找到了 JitCodeCache*，调用 InvalidateAllMethods
                type InvalidateAllFn = unsafe extern "C" fn(this: u64);
                let invalidate: InvalidateAllFn = std::mem::transmute(func_ptr);
                invalidate(code_cache_stripped);
                output_message(&format!(
                    "[jit cache] InvalidateAllMethods 调用成功: JitCodeCache={:#x} (Runtime+{:#x})",
                    code_cache_stripped, offset
                ));
                return;
            }
        }

        output_message("[jit cache] 未找到 Jit* 指针，尝试直接扫描 JitCodeCache...");
    }

    // 方案 C: 直接扫描 Runtime 找 jit_code_cache_ 指针
    // jit_code_cache_ 是一个独立字段，通常紧跟 jit_ 之后
    // 这里我们放弃精确查找，仅记录警告
    output_message("[jit cache] JIT 缓存清空跳过: 无法定位 JitCodeCache 指针");
}

/// 查找 GC ConcurrentCopying::CopyingPhase 或 MarkingPhase 符号
///
/// API > 28: CopyingPhase
/// API 23-28: MarkingPhase
unsafe fn find_gc_copying_phase() -> u64 {
    let api_level = get_android_api_level();

    let sym_name = if api_level > 28 {
        "_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv"
    } else if api_level > 22 {
        "_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv"
    } else {
        return 0; // Android 5.x 不使用 ConcurrentCopying
    };

    libart_dlsym(sym_name) as u64
}

/// 查找 Heap::CollectGarbageInternal 符号
///
/// 主 GC 入口点，GC 完成后需要同步 replacement 方法。
/// 符号签名因 Android 版本不同而异。
unsafe fn find_gc_collect_internal() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): 5-arg overload (extra uint32_t param)
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbj",
        // Android 12+ (API 31+): 4-arg overload
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEb",
        // Android 10-11 (API 29-30)
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbPKNS0_9collector14GarbageCollectorE",
        // Older variants
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_13GcCauseEb",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 Thread::RunFlipFunction 符号
///
/// 线程翻转期间需要同步 replacement 方法（moving GC 相关）。
unsafe fn find_run_flip_function() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): 带 bool 参数
        "_ZN3art6Thread15RunFlipFunctionEPS0_b",
        // Android 10-11 (API 29-30)
        "_ZN3art6Thread15RunFlipFunctionEPS0_",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 ArtMethod::GetOatQuickMethodHeader 符号
///
/// ART 通过此函数查找方法的 OAT 编译代码头。对 replacement method（堆分配），
/// 此调用可能返回错误结果或崩溃。需要拦截并对 replacement 返回 NULL。
unsafe fn find_get_oat_quick_method_header() -> u64 {
    let candidates = [
        "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm",
        // 某些 Android 版本使用 uintptr_t
        "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 FixupStaticTrampolines 或 MakeInitializedClassesVisiblyInitialized 符号
///
/// 当类完成延迟初始化时，ART 可能更新静态方法的 quickCode，
/// 从 resolution_trampoline 变为编译代码，绕过 hook。
unsafe fn find_fixup_static_trampolines() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): MakeInitializedClassesVisiblyInitialized (40 chars)
        "_ZN3art11ClassLinker40MakeInitializedClassesVisiblyInitializedEPNS_6ThreadEb",
        // Android 8-11: FixupStaticTrampolines with Thread* param (ObjPtr 版本)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ThreadENS_6ObjPtrINS_6mirror5ClassEEE",
        // Android 8-11: FixupStaticTrampolines (ObjPtr 版本, no Thread*)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ObjPtrINS_6mirror5ClassEEE",
        // Android 7: FixupStaticTrampolines (raw pointer 版本)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6mirror5ClassE",
    ];

    dlsym_first_match(&candidates)
}

// ============================================================================
// ART entrypoint classification helpers
// ============================================================================

/// Check if an address is an ART shared entrypoint (stub/bridge/nterp)
/// or resides inside libart.so.
///
/// Returns true if the address is:
/// - 0 (null)
/// - One of the known shared stubs (jni_trampoline, interpreter_bridge, resolution, nterp)
/// - Inside libart.so (e.g. other ART internal trampolines)
///
/// Compiled methods (AOT/JIT) that have independent code OUTSIDE libart.so return false.
pub(super) fn is_art_quick_entrypoint(addr: u64, bridge: &ArtBridgeFunctions) -> bool {
    if addr == 0 {
        return true;
    }
    if addr == bridge.quick_generic_jni_trampoline
        || addr == bridge.quick_to_interpreter_bridge
        || addr == bridge.quick_resolution_trampoline
        || addr == bridge.nterp_entry_point
    {
        return true;
    }
    // dladdr check: is this address in libart.so?
    is_in_libart(addr)
}

// ============================================================================
// ArtMethod resolution
// ============================================================================

/// Resolve a Java method to its ArtMethod* address.
/// Returns (art_method_ptr, is_static).
/// When `force_static` is true, skips GetMethodID and goes straight to GetStaticMethodID.
pub(super) fn resolve_art_method(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Result<(u64, bool), String> {
    let c_method = CString::new(method_name).map_err(|_| "invalid method name")?;
    let c_sig = CString::new(signature).map_err(|_| "invalid signature")?;

    unsafe {
        let cls = find_class_safe(env, class_name);

        if cls.is_null() {
            // Defensive: ensure no pending exception leaks to caller
            jni_check_exc(env);
            return Err(format!("FindClass('{}') failed", class_name));
        }

        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        // Try GetMethodID (instance method first), unless force_static
        if !force_static {
            let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);

            let method_id = get_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
            output_message(&format!(
                "[resolve_art_method] cls={:#x}, GetMethodID({}.{}{})={:#x}",
                cls as u64, class_name, method_name, signature, method_id as u64
            ));

            if !method_id.is_null() && !jni_check_exc(env) {
                // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
                let art_method = decode_method_id(env, cls, method_id as u64, false);
                delete_local_ref(env, cls);
                return Ok((art_method, false));
            }

            // Clear exception from GetMethodID failure
            jni_check_exc(env);
        }

        // Try GetStaticMethodID
        let get_static_method_id: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);

        let method_id = get_static_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());

        if !method_id.is_null() && !jni_check_exc(env) {
            // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
            let art_method = decode_method_id(env, cls, method_id as u64, true);
            delete_local_ref(env, cls);
            return Ok((art_method, true));
        }

        jni_check_exc(env);

        // Cleanup
        delete_local_ref(env, cls);

        Err(format!(
            "method not found: {}.{}{}",
            class_name, method_name, signature
        ))
    }
}

/// Read the entry_point_from_quick_compiled_code_ from ArtMethod
pub(super) unsafe fn read_entry_point(art_method: u64, offset: usize) -> u64 {
    let ptr = (art_method as usize + offset) as *const u64;
    std::ptr::read_volatile(ptr)
}

// ============================================================================
// Field cache — pre-enumerated at hook time (safe thread), used from callbacks
// ============================================================================

pub(super) struct CachedFieldInfo {
    pub(super) jni_sig: String,
    pub(super) field_id: *mut std::ffi::c_void, // jfieldID — stable across threads
    pub(super) is_static: bool,
}

unsafe impl Send for CachedFieldInfo {}
unsafe impl Sync for CachedFieldInfo {}

/// Cached field info per class: className → (fieldName → CachedFieldInfo)
pub(super) static FIELD_CACHE: Mutex<Option<HashMap<String, HashMap<String, CachedFieldInfo>>>> =
    Mutex::new(None);

/// Enumerate and cache all fields (instance + static) for a class (including inherited).
/// Must be called from a safe thread (not a hook callback).
pub(super) unsafe fn cache_fields_for_class(
    env: JniEnv,
    class_name: &str,
) {
    // Initialize cache if needed
    {
        let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        // Skip if already cached
        if guard.as_ref().unwrap().contains_key(class_name) {
            return;
        }
    }

    // Enumerate fields using JNI reflection (safe from init thread)
    let fields = match enumerate_class_fields(env, class_name) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Resolve field IDs and store in cache
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        return;
    }

    let mut field_map = HashMap::new();
    for (name, type_name, is_static) in &fields {
        let jni_sig = java_type_to_jni(type_name);
        let c_name = match CString::new(name.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let c_sig = match CString::new(jni_sig.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // IMPORTANT: Always clear pending exceptions before calling Get[Static]FieldID.
        // GetFieldID will abort (SIGABRT) if there's already a pending exception.
        jni_check_exc(env);
        let fid = if *is_static {
            get_static_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr())
        } else {
            get_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr())
        };
        if fid.is_null() {
            jni_check_exc(env); // Clear exception from failed GetFieldID
            continue;
        }
        field_map.insert(
            name.clone(),
            CachedFieldInfo {
                jni_sig,
                field_id: fid,
                is_static: *is_static,
            },
        );
    }

    delete_local_ref(env, cls);

    let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cache) = guard.as_mut() {
        cache.insert(class_name.to_string(), field_map);
    }
}

/// Enumerate fields of a class and all its superclasses via JNI reflection.
/// Returns Vec<(fieldName, typeName, is_static)>.
unsafe fn enumerate_class_fields(
    env: JniEnv,
    class_name: &str,
) -> Result<Vec<(String, String, bool)>, String> {
    use std::ffi::CStr;

    let reflect = REFLECT_IDS.get().ok_or("reflection IDs not cached")?;

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let call_int: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let push_frame: PushLocalFrameFn = jni_fn!(env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
    let pop_frame: PopLocalFrameFn = jni_fn!(env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);

    if push_frame(env, 512) < 0 {
        return Err("PushLocalFrame failed".to_string());
    }

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        pop_frame(env, std::ptr::null_mut());
        return Err("FindClass failed".to_string());
    }

    // Get reflection method IDs (system classes — FindClass is fine)
    let c_class_cls = CString::new("java/lang/Class").unwrap();
    let c_field_cls = CString::new("java/lang/reflect/Field").unwrap();
    let class_cls = find_class(env, c_class_cls.as_ptr());
    let field_cls = find_class(env, c_field_cls.as_ptr());

    let c_get_fields = CString::new("getFields").unwrap();
    let c_get_fields_sig = CString::new("()[Ljava/lang/reflect/Field;").unwrap();
    let c_get_declared_fields = CString::new("getDeclaredFields").unwrap();
    let c_get_name = CString::new("getName").unwrap();
    let c_str_sig = CString::new("()Ljava/lang/String;").unwrap();
    let c_get_type = CString::new("getType").unwrap();
    let c_get_type_sig = CString::new("()Ljava/lang/Class;").unwrap();
    let c_get_mods = CString::new("getModifiers").unwrap();
    let c_get_mods_sig = CString::new("()I").unwrap();

    let get_fields_mid = get_mid(env, class_cls, c_get_fields.as_ptr(), c_get_fields_sig.as_ptr());
    let get_declared_fields_mid = get_mid(env, class_cls, c_get_declared_fields.as_ptr(), c_get_fields_sig.as_ptr());
    let field_get_name_mid = get_mid(env, field_cls, c_get_name.as_ptr(), c_str_sig.as_ptr());
    let field_get_type_mid = get_mid(env, field_cls, c_get_type.as_ptr(), c_get_type_sig.as_ptr());
    let field_get_mods_mid = get_mid(env, field_cls, c_get_mods.as_ptr(), c_get_mods_sig.as_ptr());

    jni_check_exc(env);

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Helper: extract fields from a Field[] array
    let mut extract_fields = |arr: *mut std::ffi::c_void| {
        if arr.is_null() { return; }
        let len = get_arr_len(env, arr);
        for i in 0..len {
            let field = get_arr_elem(env, arr, i);
            if field.is_null() { continue; }

            // getName()
            let name_jstr = call_obj(env, field, field_get_name_mid, std::ptr::null());
            if name_jstr.is_null() { continue; }
            let name_chars = get_str(env, name_jstr, std::ptr::null_mut());
            let name = CStr::from_ptr(name_chars).to_string_lossy().to_string();
            rel_str(env, name_jstr, name_chars);

            if seen.contains(&name) { continue; }

            // getModifiers() — check for static (0x0008)
            let modifiers = if !field_get_mods_mid.is_null() {
                call_int(env, field, field_get_mods_mid, std::ptr::null())
            } else {
                0
            };
            let is_static = (modifiers & 0x0008) != 0;

            // getType().getName()
            let type_cls_obj = call_obj(env, field, field_get_type_mid, std::ptr::null());
            if type_cls_obj.is_null() { continue; }
            let type_name_jstr = call_obj(env, type_cls_obj, reflect.class_get_name_mid, std::ptr::null());
            if type_name_jstr.is_null() { continue; }
            let tc = get_str(env, type_name_jstr, std::ptr::null_mut());
            let type_name = CStr::from_ptr(tc).to_string_lossy().to_string();
            rel_str(env, type_name_jstr, tc);

            seen.insert(name.clone());
            results.push((name, type_name, is_static));
        }
    };

    // getDeclaredFields() — own fields (including private, static)
    if !get_declared_fields_mid.is_null() {
        let arr = call_obj(env, cls, get_declared_fields_mid, std::ptr::null());
        if jni_check_exc(env) { /* skip */ }
        else { extract_fields(arr); }
    }

    // getFields() — all public inherited fields (including static)
    if !get_fields_mid.is_null() {
        let arr = call_obj(env, cls, get_fields_mid, std::ptr::null());
        if jni_check_exc(env) { /* skip */ }
        else { extract_fields(arr); }
    }

    pop_frame(env, std::ptr::null_mut());
    Ok(results)
}

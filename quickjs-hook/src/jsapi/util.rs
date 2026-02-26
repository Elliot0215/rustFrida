//! jsapi 共用工具函数

/// Check if [addr, addr+size) is accessible using mincore(2).
/// Returns false for null/zero or unmapped pages.
pub(crate) fn is_addr_accessible(addr: u64, size: usize) -> bool {
    if addr == 0 || size == 0 {
        return false;
    }
    unsafe {
        const PAGE_SIZE: usize = 0x1000;
        let page_addr = (addr as usize) & !(PAGE_SIZE - 1);
        let end = (addr as usize).wrapping_add(size);
        let region_len = end.saturating_sub(page_addr);
        let pages = (region_len + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut vec = vec![0u8; pages];
        libc::mincore(
            page_addr as *mut libc::c_void,
            region_len,
            vec.as_mut_ptr() as *mut _,
        ) == 0
    }
}

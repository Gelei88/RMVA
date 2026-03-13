use core::ffi::c_void;
use std::result::Result;

/// `arena-allocator` :可能发生的错误。
///
/// `ArenaError` 枚举封装了与 `Arena` 或 `TypedArena` 交互时可能遇到的不同类型的错误。
/// 这些错误通常源于内存预留、保护相关问题，耗尽预留内存时
///
/// # 变体
///
/// - `ReserveFailed(String)`: 当虚拟内存的初始预留失败时发生此错误。
///   关联的字符串提供了底层问题的描述。
///
/// - `ProtectionFailed(String)`: 当内存保护机制失败时返回此错误。
///   这在调试模式中特别相关，其中内存保护用于检测释放后使用错误。
///   关联的字符串提供了失败的详细解释。
///
/// - `OutOfReservedMemory`: 当分配请求超过可用预留内存时触发此错误。
///   它表示已耗尽其预留的虚拟内存，无法在没有进一步操作的情况下容纳额外分配。
#[derive(Debug)]
pub enum ArenaError {
    ReserveFailed(String),
    ProtectionFailed(String),
    OutOfReservedMemory,
}

#[cfg(not(target_os = "windows"))]
mod posix {
    use crate::ArenaError;
    use core::ffi::{c_void, CStr};
    use core::ptr::null_mut;
    use libc::{mmap, mprotect, strerror_r, sysconf};
    use libc::{MAP_ANON, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, _SC_PAGESIZE};
    use std::io;

    const MAP_FAILED: *mut c_void = !0 as *mut c_void;

    pub(crate) fn get_page_size() -> usize {
        unsafe { sysconf(_SC_PAGESIZE) as usize }
    }

    fn get_last_error_code() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn get_last_error_message() -> String {
        let err_code = get_last_error_code();
        let mut buf = [0i8; 256];
        unsafe {
            strerror_r(err_code, buf.as_mut_ptr(), buf.len());
            let c_str = CStr::from_ptr(buf.as_ptr());
            c_str.to_string_lossy().into_owned()
        }
    }

    pub(crate) fn reserve_range(size: usize) -> Result<*mut c_void, ArenaError> {
        let ptr = unsafe { mmap(null_mut(), size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0) };
        if ptr == MAP_FAILED {
            return Err(ArenaError::ReserveFailed(get_last_error_message()));
        }
        Ok(ptr)
    }

    pub(crate) fn commit_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_READ | PROT_WRITE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_NONE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_NONE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        if size > 0 {
            let result = unsafe { mprotect(ptr, size, PROT_READ | PROT_WRITE) };
            if result != 0 {
                return Err(ArenaError::ProtectionFailed(get_last_error_message()));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use crate::ArenaError;
    use core::{ffi::c_void, mem::zeroed};
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr::null_mut};

    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x00000100;
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    const MEM_COMMIT: u32 = 0x00001000;
    const MEM_DECOMMIT: u32 = 0x00004000;
    const MEM_RESERVE: u32 = 0x00002000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READWRITE: u32 = 0x04;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SYSTEM_INFO {
        wProcessorArchitecture: u16,
        wReserved: u16,
        dwPageSize: u32,
        lpMinimumApplicationAddress: *mut u8,
        lpMaximumApplicationAddress: *mut u8,
        dwActiveProcessorMask: *mut u64,
        dwNumberOfProcessors: u32,
        dwProcessorType: u32,
        dwAllocationGranularity: u32,
        wProcessorLevel: u16,
        wProcessorRevision: u16,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemInfo(lpSystemInfo: *mut SYSTEM_INFO);
        fn GetLastError() -> u32;
        fn FormatMessageW(
            dwFlags: u32,
            lpSource: *const u16,
            dwMessageId: u32,
            dwLanguageId: u32,
            lpBuffer: *mut u16,
            nSize: u32,
            Arguments: *mut *mut u8,
        ) -> u32;
        fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn VirtualAlloc(
            lpAddress: *mut core::ffi::c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut core::ffi::c_void;
        fn VirtualProtect(
            lpAddress: *mut core::ffi::c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
        fn VirtualFree(lpAddress: *mut core::ffi::c_void, dwSize: usize, dwFreeType: u32) -> i32;
    }

    fn get_system_info() -> SYSTEM_INFO {
        let mut info: SYSTEM_INFO = unsafe { zeroed() };
        unsafe {
            GetSystemInfo(&mut info);
        }
        info
    }

    pub(crate) fn get_page_size() -> usize {
        let info = get_system_info();
        info.dwPageSize as usize
    }

    fn get_last_error_message() -> String {
        unsafe {
            let error_code = GetLastError();
            if error_code == 0 {
                return String::new();
            }

            let mut buf: *mut u16 = null_mut();
            let size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                error_code,
                0,
                &mut buf as *mut *mut u16 as *mut u16,
                0,
                null_mut(),
            );

            if size == 0 {
                return format!("Unknown error code: {}", error_code);
            }

            let message = OsString::from_wide(core::slice::from_raw_parts(buf, size as usize))
                .to_string_lossy()
                .into_owned();
            LocalFree(buf as *mut _);
            message
        }
    }

    pub(crate) fn reserve_range(size: usize) -> Result<*mut c_void, ArenaError> {
        let ptr = unsafe { VirtualAlloc(null_mut(), size, MEM_RESERVE, PAGE_READWRITE) };
        if ptr.is_null() {
            return Err(ArenaError::ReserveFailed(get_last_error_message()));
        }
        Ok(ptr)
    }

    pub(crate) fn commit_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let success = unsafe { VirtualAlloc(ptr, size, MEM_COMMIT, PAGE_READWRITE) };
        if success.is_null() {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let success = unsafe { VirtualFree(ptr, size, MEM_DECOMMIT) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let mut old_protect = 0u32;
        let success = unsafe { VirtualProtect(ptr, size, PAGE_NOACCESS, &mut old_protect) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        if size > 0 {
            let mut old_protect = 0u32;
            let success = unsafe { VirtualProtect(ptr, size, PAGE_READWRITE, &mut old_protect) };
            if success == 0 {
                return Err(ArenaError::ProtectionFailed(get_last_error_message()));
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) use posix::*;

#[cfg(target_os = "windows")]
pub(crate) use windows::*;

#[derive(Copy, Clone)]
struct VmRange<'a> {
    ptr: *mut c_void,
    reserved_size: usize,
    committed_size: usize,
    pos: usize,
    page_size: usize,
    marker: core::marker::PhantomData<&'a c_void>,
}

impl<'a> VmRange<'a> {
    pub fn new(reserved_size: usize) -> Result<Self, ArenaError> {
        let page_size = get_page_size();
        let ptr = reserve_range(std::cmp::max(reserved_size, page_size))?;
        Ok(Self {
            ptr,
            reserved_size,
            committed_size: 0,
            pos: 0,
            marker: core::marker::PhantomData,
            page_size,
        })
    }

    #[inline]
    fn align_pow2(x: usize, b: usize) -> usize {
        (x + b - 1) & !(b - 1)
    }

    /// 分配一个原始内存块。
    ///
    /// # 安全
    /// 返回的数据是未初始化的。调用者必须确保数据被正确初始化。
    pub(crate) unsafe fn alloc_raw(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        let new_pos = self.pos + Self::align_pow2(size, alignment);
        let commit_size = Self::align_pow2(size, self.page_size);

        if self.committed_size + commit_size > self.reserved_size {
            return Err(ArenaError::OutOfReservedMemory);
        }

        // If we have already committed the memory, we can just return a slice
        if new_pos < self.committed_size {
            let return_slice = std::slice::from_raw_parts_mut(self.ptr as *mut u8, size);
            self.pos = new_pos;
            return Ok(return_slice);
        }

        commit_memory(self.ptr.add(self.committed_size), commit_size)?;

        self.committed_size += commit_size;
        let return_slice = std::slice::from_raw_parts_mut(self.ptr.add(self.pos) as *mut u8, size);
        self.pos = new_pos;
        Ok(return_slice)
    }

    /// 分配一个 `T` 元素的数组。
    ///
    /// # 安全
    /// 返回的数据是未初始化的。调用者必须确保数据被正确初始化。
    pub(crate) unsafe fn alloc_array<T: Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        let size = count * core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = self.alloc_raw(size, alignment)?;
        let ptr = slice.as_mut_ptr() as *mut T;
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, count) })
    }

    /// 分配一个 `T` 元素的数组，并使用默认值初始化它们。
    pub(crate) fn alloc_array_init<T: Default + Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        let size = count * core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = unsafe { self.alloc_raw(size, alignment)? };
        let ptr = slice.as_mut_ptr() as *mut T;
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, count) };

        for v in slice.iter_mut() {
            *v = T::default();
        }

        Ok(slice)
    }

    /// 分配一个 `T` 的单个实例。
    ///
    /// # 安全
    /// 返回的数据是未初始化的。调用者必须确保数据被正确初始化。c<T: Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        let size = core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = self.alloc_raw(size, alignment)?;
        let ptr = slice.as_mut_ptr() as *mut T;
        Ok(unsafe { &mut *ptr })
    }

    pub(crate) fn alloc_init<T: Default + Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        let size = core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = unsafe { self.alloc_raw(size, alignment)? };
        let ptr = slice.as_mut_ptr() as *mut T;
        unsafe { ptr.write(T::default()) };
        Ok(unsafe { &mut *ptr })
    }

    #[inline]
    pub(crate) fn rewind(&mut self) {
        self.pos = 0;
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect(&mut self) {
        protect_memory(self.ptr, self.committed_size).unwrap();
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect(&mut self) {
        unprotect_memory(self.ptr, self.committed_size).unwrap();
    }

    #[inline]
    pub(crate) fn decomit(&mut self) -> Result<(), ArenaError> {
        decommit_memory(self.ptr, self.committed_size)?;
        self.committed_size = 0;
        self.pos = 0;
        Ok(())
    }
}

/// 一个用于高效分配管理的内存arena。
///
/// `Arena` 结构体管理一个预留的虚拟内存块，实现快速、连续的分配。这个结构特别适用于需要许多小分配的场景，因为它最小化了开销和碎片。
///
/// # 主要用例
///
/// `Arena` 设计用于两种主要的分配模式：
///
/// 1. **长期存在的分配**: 当分配预期持续到程序结束时。这种用例受益于的内存高效管理，避免频繁释放的开销。
///   
/// 2. **非常短暂的分配**: 当分配是临时的，并且在分配不再需要后“回退”分配器。这种模式适用于创建和丢弃大量临时对象的场景，因为它允许快速清理和重新使用分配的内存。
///
/// # 字段
///
/// - `current`: 活动的 `VmRange`，跟踪预留内存中当前分配的范围。从这个范围执行分配。
///
/// - `prev`: 仅在调试模式下使用的二级 `VmRange`。这个范围镜像 `current` 范围，并在释放后受到保护，允许检测释放后使用错误。
///   在发布模式下，这个字段不使用，内存保护被禁用以最大化性能。
///
/// # 用法
///
/// `Arena` 通过 `Arena::new` 函数使用指定的尺寸初始化。虽然整个尺寸在虚拟内存中预留，但物理内存仅在需要时以页面大小的块提交。这种设计确保内存占用保持最小，直到实际分配发生。
///
/// 在调试构建中，启用额外的内存保护来捕获潜在的内存安全问题，如释放后使用，尽管这以增加内存使用为代价。这个功能在发布构建中自动禁用以获得最佳性能。
pub struct Arena<'a> {
    current: VmRange<'a>,
    //#[cfg(debug_assertions)]
    prev: VmRange<'a>,
}

impl<'a> Arena<'a> {
    /// 使用指定的尺寸初始化一个新的 `Arena`。`size` 参数定义了预留虚拟内存的数量。
    /// 建议选择一个大的尺寸，因为这个预留不会立即消耗物理内存。在 64 位系统上，预留几 GB 通常是可以接受的。物理内存随着分配发生而以页面大小的块递增提交。
    ///
    /// 在调试模式下，释放的内存受到保护以检测释放后使用错误，导致内存预留翻倍。这个保护在发布模式下被禁用。
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        let current = VmRange::new(size)?;
        #[cfg(debug_assertions)]
        let prev = VmRange::new(size)?;

        Ok(Self {
            current,
            #[cfg(debug_assertions)]
            prev,
        })
    }

    /// 在arena中分配一个原始内存块。
    ///
    /// 这个函数在arena内分配一个未初始化的内存块。块的大小和对齐由调用者指定。分配的内存是连续的，可以用于任何需要原始、无类型数据的目的。
    ///
    /// # 安全
    /// 返回的内存是未初始化的，调用者有责任确保在使用前正确初始化内存。未能这样做可能导致未定义行为。
    pub unsafe fn alloc_raw(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        self.current.alloc_raw(size, alignment)
    }

    /// 在arena中分配一个 `T` 元素的数组。
    ///
    /// 这个函数为类型 `T` 的元素数组分配未初始化的内存。元素的数量由 `count` 参数指定。内存是连续的，并为类型 `T` 正确对齐。
    ///
    /// # 安全
    /// 返回的数组是未初始化的，调用者有责任在使用前初始化元素。使用未初始化的数据可能导致未定义行为。在arena回退后，对这个数组的所有引用都变得无效。
    pub unsafe fn alloc_array<T: Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        self.current.alloc_array(count)
    }

    /// 在arena中分配一个 `T` 的单个实例。
    ///
    /// 这个函数为类型 `T` 的单个实例分配未初始化的内存。
    ///
    /// # 安全
    /// 返回的实例是未初始化的，调用者必须确保在使用前初始化它。未初始化的内存如果被访问可能导致未定义行为。
    pub unsafe fn alloc<T: Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        self.current.alloc()
    }

    /// 在arena中分配一个 `T` 的单个实例，并使用默认值初始化它。
    ///
    /// 这个函数为类型 `T` 的单个实例分配内存，并使用 `T::default()` 初始化它。
    pub fn alloc_init<T: Default + Sized>(&mut self) -> Result<&'a mut T, ArenaError> {
        self.current.alloc_init()
    }

    /// 在arena中分配一个 `T` 元素的数组，并使用默认值初始化它们。
    ///
    /// 这个函数为类型 `T` 的元素数组分配内存，并使用 `T::default()` 初始化每个元素。
    pub fn alloc_array_init<T: Default + Sized>(
        &mut self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        self.current.alloc_array_init(count)
    }

    /// 将arena回退到其初始状态。
    ///
    /// 这个方法将分配位置重置到arena的开始，而不释放内存。调用 `rewind` 后，对arena中之前分配内存的所有引用都应被视为无效，因为任何后续分配都将覆盖这个内存。
    ///
    /// # 内存安全
    ///
    /// 在调试模式下，调用 `rewind` 将保护已回退的内存，帮助捕获释放后使用错误。对在 `rewind` 之前分配的内存的任何访问都将导致崩溃，如下面的示例所示：
    ///
    /// ```
    /// use arena_allocator::Arena;
    ///
    /// let mut arena = Arena::new(16 * 1024).unwrap();
    /// let t = arena.alloc_init::<u32>().unwrap();
    /// *t = 42;
    /// arena.rewind();
    /// //*t = 43; // 这将在调试模式下崩溃
    /// ```
    ///
    /// # 用法
    ///
    /// 这个方法特别适用于arena用于非常短暂的分配的场景，这些分配被批量丢弃。通过回退arena，分配器可以快速重置并重新使用预留的内存，而没有释放和重新分配的开销。
    ///
    /// 在发布模式下，内存保护机制被禁用以确保最佳性能，但在调试模式下，额外的检查有助于识别不正确的内存使用模式。
    #[cfg(debug_assertions)]
    pub fn rewind(&mut self) {
        self.current.protect();

        std::mem::swap(&mut self.current, &mut self.prev);

        // Unprotect the new current range and rewind the position to the start
        self.current.unprotect();
        self.current.rewind();
    }

    #[cfg(not(debug_assertions))]
    pub fn rewind(&mut self) {
        self.current.rewind();
    }
}

impl Drop for Arena<'_> {
    #[cfg(debug_assertions)]
    fn drop(&mut self) {
        self.current.decomit().unwrap();
        self.prev.decomit().unwrap();
    }

    #[cfg(not(debug_assertions))]
    fn drop(&mut self) {
        self.current.decomit().unwrap();
    }
}

/// 一个类型特定的内存arena，用于高效分配 `T` 元素。
///
/// `TypedArena` 是一个专门的内存分配器，设计用于管理单个类型 `T` 的对象。
/// 它建立在底层 `Arena` 之上，提供类型安全和使用 `T::default()` 的分配对象的自动初始化。这使它理想于需要高效分配大量类型 `T` 对象的场景，无论是用于长期存储还是用于快速回收的短暂使用。
///
/// # 类型参数
///
/// - `T`: 这个arena将管理的对象的类型。`T` 必须实现 `Default` 和 `Sized` trait，确保实例可以使用默认值创建，并且它们的尺寸在编译时已知。
///
/// # 主要用例
///
/// `TypedArena` 特别适用于以下情况：
///
/// 1. **长期存在的分配**: 对象被分配一次并使用到程序结束。
/// 2. **短暂的分配**: 对象被分配然后快速丢弃，整个arena被回退以供重用。这对于需要快速回收的临时数据结构是高效的。
///
/// # 示例
///
/// ```rust
/// use arena_allocator::TypedArena;
///
/// let mut arena = TypedArena::<u32>::new(1024 * 1024).unwrap();
/// let item = arena.alloc().unwrap();
/// *item = 42;
///
/// let array = arena.alloc_array(10).unwrap();
/// for i in 0..10 {
///     array[i] = i as u32;
/// }
///
/// arena.rewind(); // 所有之前的分配现在都无效。
/// ```
pub struct TypedArena<'a, T: Default + Sized> {
    arena: Arena<'a>,
    ptr_type: core::marker::PhantomData<&'a T>,
}

impl<'a, T: Default + Sized> TypedArena<'a, T> {
    /// 使用指定的尺寸创建一个新的 `TypedArena`。
    ///
    /// `size` 参数指定在arena中预留的内存量。建议选择一个大的尺寸，特别是对于将分配许多类型 `T` 对象的场景。预留的内存不会立即提交，所以预留超过必要的不会消耗物理内存，直到分配发生。
    ///
    /// # 错误
    /// 如果底层内存预留失败，这个函数将返回一个 `ArenaError`。
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            arena: Arena::new(size)?,
            ptr_type: core::marker::PhantomData,
        })
    }

    /// 在arena中分配一个 `T` 的单个实例，并使用默认值初始化它。
    ///
    /// 这个函数为 `T` 的实例分配内存，并使用 `T::default()` 初始化它。
    /// 返回的引用指向初始化的对象，可以立即使用。
    ///
    /// # 错误
    /// 如果内存分配失败，这个函数将返回一个 `ArenaError`。
    pub fn alloc(&mut self) -> Result<&'a mut T, ArenaError> {
        self.arena.alloc_init()
    }

    /// 在arena中分配一个 `T` 元素的数组，并使用默认值初始化它们。
    ///
    /// 这个函数为 `T` 元素的数组分配内存，并使用 `T::default()` 初始化每个元素。
    /// 返回的切片指向初始化的数组，可以立即使用。
    ///
    /// # 错误
    /// 如果内存分配失败，这个函数将返回一个 `ArenaError`。
    pub fn alloc_array(&mut self, count: usize) -> Result<&'a mut [T], ArenaError> {
        self.arena.alloc_array_init(count)
    }

    /// 将arena回退到其初始状态，使所有之前的分配无效。
    ///
    /// 这个方法重置arena，允许它被重用于新的分配。所有之前分配的对象在这个操作后变得无效，任何尝试访问它们的操作都将导致未定义行为。在调试模式下，无效对象的内存受到保护以帮助捕获释放后使用错误。
    ///
    /// # 用法
    /// `rewind` 特别适用于arena用于临时分配的场景，这些分配需要快速丢弃和回收。
    pub fn rewind(&mut self) {
        self.arena.rewind();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_arena() {
        let mut arena = Arena::new(16 * 1024).unwrap();
        let slice = unsafe { arena.alloc_raw(1024, 16).unwrap() };
        assert_eq!(slice.len(), 1024);
        assert_eq!(slice.as_ptr() as usize % 16, 0);
        assert!(slice.as_ptr() != std::ptr::null_mut());
    }

    #[test]
    fn test_fail_reserve() {
        let result = Arena::new(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_fail_commit() {
        let size = 16 * 1024;
        let mut arena = Arena::new(size).unwrap();
        let result = unsafe { arena.alloc_raw(size * 2, 16) };
        assert!(result.is_err());
    }

    #[test]
    fn test_typed_arena() {
        let mut arena = TypedArena::<u32>::new(32 * 1024).unwrap();
        let single = arena.alloc().unwrap();
        assert_eq!(*single, 0);
        *single = 42;
        assert_eq!(*single, 42);

        let array = arena.alloc_array(1024).unwrap();
        assert_eq!(array.len(), 1024);
        for i in 0..1024 {
            assert_eq!(array[i], 0);
            array[i] = i as u32;
        }
        for i in 0..1024 {
            assert_eq!(array[i], i as u32);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(test)]
mod macos_linux_tests {
    use super::*;
    use libc::{fork, waitpid, SIGSEGV, WIFEXITED, WIFSIGNALED};
    use std::process;

    #[test]
    fn test_crash_handling() {
        unsafe {
            let pid = fork();
            if pid == -1 {
                panic!("Failed to fork process");
            } else if pid == 0 {
                let mut arena = TypedArena::<u32>::new(32 * 1024).unwrap();
                let single = arena.alloc().unwrap();
                *single = 42;
                arena.rewind();
                *single = 43; // will crash here as trying to write to protected memory
                println!("Single: {}", *single);
            } else {
                // Parent process
                let mut status = 0;
                waitpid(pid, &mut status, 0);
                if WIFSIGNALED(status) && libc::WTERMSIG(status) == SIGSEGV {
                    println!("Child process crashed as expected");
                } else if WIFEXITED(status) {
                    println!("Child process exited normally, but crash was expected");
                    process::exit(1); // Mark test as failed if child didn't crash
                }
            }
        }
    }
}
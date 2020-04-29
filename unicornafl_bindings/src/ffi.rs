#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::pin::Pin;
use bitflags::bitflags;
use libc::{c_char, c_int};

pub type uc_handle = *mut c_void;
pub type uc_hook = *mut c_void;
pub type uc_context = *mut c_void;

extern "C" {
    pub fn uc_version(major: *mut u32, minor: *mut u32) -> u32;
    pub fn uc_arch_supported(arch: Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine: *mut uc_handle) -> uc_error;
    pub fn uc_close(engine: uc_handle) -> uc_error;
    pub fn uc_free(mem: libc::size_t) -> uc_error;
    pub fn uc_errno(engine: uc_handle) -> uc_error;
    pub fn uc_strerror(error_code: uc_error) -> *const c_char;
    pub fn uc_reg_write(engine: uc_handle, regid: c_int, value: *const c_void) -> uc_error;
    pub fn uc_reg_read(engine: uc_handle, regid: c_int, value: *mut c_void) -> uc_error;
    pub fn uc_mem_write(
        engine: uc_handle,
        address: u64,
        bytes: *const u8,
        size: libc::size_t,
    ) -> uc_error;
    pub fn uc_mem_read(
        engine: uc_handle,
        address: u64,
        bytes: *mut u8,
        size: libc::size_t,
    ) -> uc_error;
    pub fn uc_mem_map(engine: uc_handle, address: u64, size: libc::size_t, perms: u32) -> uc_error;
    pub fn uc_mem_map_ptr(
        engine: uc_handle,
        address: u64,
        size: libc::size_t,
        perms: u32,
        ptr: *mut c_void,
    ) -> uc_error;
    pub fn uc_mem_unmap(engine: uc_handle, address: u64, size: libc::size_t) -> uc_error;
    pub fn uc_mem_protect(engine: uc_handle, address: u64, size: libc::size_t, perms: u32)
        -> uc_error;
    pub fn uc_mem_regions(
        engine: uc_handle,
        regions: *const *const MemRegion,
        count: *mut u32,
    ) -> uc_error;
    pub fn uc_emu_start(
        engine: uc_handle,
        begin: u64,
        until: u64,
        timeout: u64,
        count: libc::size_t,
    ) -> uc_error;
    pub fn uc_emu_stop(engine: uc_handle) -> uc_error;
    pub fn uc_hook_add(
        engine: uc_handle,
        hook: *mut uc_hook,
        hook_type: HookType,
        callback: *mut c_void,
        user_data: *mut c_void,
        begin: u64,
        end: u64,
        ...
    ) -> uc_error;
    pub fn uc_hook_del(engine: uc_handle, hook: uc_hook) -> uc_error;
    pub fn uc_query(engine: uc_handle, query_type: Query, result: *mut libc::size_t) -> uc_error;
    pub fn uc_context_alloc(engine: uc_handle, context: *mut uc_context) -> uc_error;
    pub fn uc_context_save(engine: uc_handle, context: uc_context) -> uc_error;
    pub fn uc_context_restore(engine: uc_handle, context: uc_context) -> uc_error;
    pub fn uc_afl_forkserver_start(
        engine: uc_handle,
        exits: *const u64,
        exit_count: libc::size_t
    ) -> AflRet;
    pub fn uc_afl_fuzz(
        engine: uc_handle, 
        input_file: *const i8,
        place_input_callback: *mut c_void,
        exits: *const u64,
        exit_count: libc::size_t,
        validate_crash_callback: *mut c_void,
        always_validate: bool,
        persistent_iters: u32,
        data: *mut c_void
    ) -> AflRet;
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum uc_error {
    OK = 0,
    NOMEM = 1,
    ARCH = 2,
    HANDLE = 3,
    MODE = 4,
    VERSION = 5,
    READ_UNMAPPED = 6,
    WRITE_UNMAPPED = 7,
    FETCH_UNMAPPED = 8,
    HOOK = 9,
    INSN_INVALID = 10,
    MAP = 11,
    WRITE_PROT = 12,
    READ_PROT = 13,
    FETCH_PROT = 14,
    ARG = 15,
    READ_UNALIGNED = 16,
    WRITE_UNALIGNED = 17,
    FETCH_UNALIGNED = 18,
    HOOK_EXIST = 19,
    RESOURCE = 20,
    EXCEPTION = 21,
}

impl uc_error {
    pub fn to_result(&self) -> Result<(), crate::UnicornError> {
        match self {
            uc_error::OK => Ok(()),
            _ => Err(crate::UnicornError::Internal)
        }
    }
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum AflRet {
    ERROR = 0,
    CHILD = 1,
    NO_AFL = 2,
    FINISHED = 3,
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum MemType {
    READ = 16,
    WRITE = 17,
    FETCH = 18,
    READ_UNMAPPED = 19,
    WRITE_UNMAPPED = 20,
    FETCH_UNMAPPED = 21,
    WRITE_PROT = 22,
    READ_PROT = 23,
    FETCH_PROT = 24,
    READ_AFTER = 25,
}

#[repr(i32)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum HookType {
    INTR = 1,
    INSN = 2,
    CODE = 4,
    BLOCK = 8,
    MEM_READ_UNMAPPED = 16,
    MEM_WRITE_UNMAPPED = 32,
    MEM_FETCH_UNMAPPED = 64,
    MEM_READ_PROT = 128,
    MEM_WRITE_PROT = 256,
    MEM_FETCH_PROT = 512,
    MEM_READ = 1024,
    MEM_WRITE = 2048,
    MEM_FETCH = 4096,
    MEM_READ_AFTER = 8192,
    INSN_INVALID = 16384,
    MEM_UNMAPPED = 112,
    MEM_PROT = 896,
    MEM_READ_INVALID = 144,
    MEM_WRITE_INVALID = 288,
    MEM_FETCH_INVALID = 576,
    MEM_INVALID = 1008,
    MEM_VALID = 7168,
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Query {
    MODE = 1,
    PAGE_SIZE = 2,
    ARCH = 3,
}

bitflags! {
#[repr(C)]
pub struct Protection : u32 {
        const NONE = 0;
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const ALL = 7;
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// The start address of the region (inclusive).
    pub begin: u64,
    /// The end address of the region (inclusive).
    pub end: u64,
    /// The memory permissions of the region.
    pub perms: Protection,
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Arch {
    ARM = 1,
    ARM64 = 2,
    MIPS = 3,
    X86 = 4,
    PPC = 5,
    SPARC = 6,
    M68K = 7,
    MAX = 8,
}


#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Mode {

    LITTLE_ENDIAN = 0,
    BIG_ENDIAN = 1073741824,

    // use LITTLE_ENDIAN.
    // MODE_ARM = 0,
    THUMB = 16,
    MCLASS = 32,
    V8 = 64,
    ARM926 = 128,
    ARM946 = 256,
    ARM1176 = 512,
    // (assoc) MICRO = 16,
    // (assoc) MIPS3 = 32,
    // (assoc) MIPS32R6 = 64,
    MIPS32 = 4,
    MIPS64 = 8,
    MODE_16 = 2,
    // (assoc) MODE_32 = 4,
    // (assoc) MODE_64 = 8,
    // (assoc) PPC32 = 4,
    // (assoc) PPC64 = 8,
    // (assoc) QPX = 16,
    // (assoc) SPARC32 = 4,
    // (assoc) SPARC64 = 8,
    // (assoc) V9 = 16,
}

impl Mode {
    pub const MICRO: Mode = Mode::THUMB;
    pub const MIPS3: Mode = Mode::MCLASS;
    pub const MIPS32R6: Mode = Mode::V8;
    pub const MODE_32: Mode = Mode::MIPS32;
    pub const MODE_64: Mode = Mode::MIPS64;
    pub const PPC32: Mode = Mode::MIPS32;
    pub const PPC64: Mode = Mode::MIPS64;
    pub const QPX: Mode = Mode::THUMB;
    pub const SPARC32: Mode = Mode::MIPS32;
    pub const SPARC64: Mode = Mode::MIPS64;
    pub const V9: Mode = Mode::THUMB;
}

pub struct CodeHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, u64, u32)>
}

pub struct MemHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, MemType, u64, usize, i64)>
}

pub struct AflFuzzCallback<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub input_callback: Box<dyn FnMut(crate::UnicornHandle<D>, &[u8], i32) -> bool>,
    pub validate_callback: Box<dyn FnMut(crate::UnicornHandle<D>, uc_error, &[u8], i32) -> bool>
}

pub extern "C" fn code_hook_proxy<D>(uc: uc_handle, address: u64, size: u32, user_data: *mut CodeHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, address, size);
}

pub extern "C" fn mem_hook_proxy<D>(uc: uc_handle, mem_type: MemType, address: u64, size: u32, value: i64, user_data: *mut MemHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, mem_type, address, size as usize, value);
}

pub extern "C" fn input_placement_callback_proxy<D>(uc: uc_handle,
    input: *const u8,
    input_len: c_int,
    persistent_round: c_int,
    user_data: *mut AflFuzzCallback<D>) -> bool {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).input_callback };
    let safe_input = unsafe { std::slice::from_raw_parts(input, input_len as usize) };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, safe_input, persistent_round)
}

pub extern "C" fn crash_validation_callback_proxy<D>(uc: uc_handle,
    unicorn_result: uc_error,
    input: *const u8,
    input_len: c_int,
    persistent_round: c_int,
    user_data: *mut AflFuzzCallback<D>
    ) -> bool {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).validate_callback };
    assert_eq!(uc, unicorn.uc);
    let safe_input = unsafe { std::slice::from_raw_parts(input, input_len as usize) };
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, unicorn_result, safe_input, persistent_round) 
}
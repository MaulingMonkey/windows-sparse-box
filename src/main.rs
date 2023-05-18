#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]

extern crate alloc;
extern crate std;

use bytemuck::Zeroable;

use winapi::shared::basetsd::{SIZE_T, ULONG64, DWORD64};
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::ULONG;

use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::memoryapi::{VirtualFree, CreateFileMappingW, UnmapViewOfFileEx};
use winapi::um::sysinfoapi::{SYSTEM_INFO, GetSystemInfo};
use winapi::um::winnt::{MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READONLY, MEM_PHYSICAL, HANDLE, PVOID, MEM_COMMIT, PAGE_READWRITE};

use core::alloc::Layout;
use core::mem::size_of;
use core::ops::Deref;
use core::ptr::{NonNull, null_mut};



fn main() {
    let size = 1 << 40; // 1 TiB
    let mut demo = SparseBox::<u8>::new_zeroed_slice(size);
    demo.copy_from_slice_at(size/2-10, &[1u8; 21][..]);
    assert_eq!(0u8, demo[size/3]);
    assert_eq!(1u8, demo[size/2]);
}



pub struct SparseBox<T: ?Sized> {
    data:               NonNull<T>,
    chunk_size:         usize,
    total_size:         usize,
    zeroed_chunk:       FileMapping,
}

impl<T: ?Sized> Drop for SparseBox<T> {
    fn drop(&mut self) {
        for offset in (0 .. self.total_size).step_by(self.chunk_size) {
            let chunk_base = unsafe { self.data.as_ptr().cast::<u8>().add(offset).cast() };

            let success = unsafe { UnmapViewOfFileEx(chunk_base, 0) };
            if success == 0 {
                // If UnmapViewOfFileEx failed, assume we replaced that chunk's file view with unique committed memory
                let success = unsafe { VirtualFree(chunk_base, 0, MEM_RELEASE) };
                assert!(success != 0, "VirtualFree({chunk_base:?}, 0, MEM_RELEASE) failed with GetLastError() == {}", get_last_error());
            }
        }

        // zeroed_chunk will drop to CloseHandle(zeroed_chunk.0)
    }
}

impl<T> SparseBox<T> {
    pub fn new_zeroed_slice(len: usize) -> SparseBox<[T]> where T : Zeroable { Self::try_new_zeroed_slice(len).unwrap() }

    pub fn try_new_zeroed_slice(len: usize) -> Result<SparseBox<[T]>, SparseBoxError> where T : Zeroable {
        let layout = Layout::array::<T>(len)?;
        //let chunk_size_32 = get_system_info().dwPageSize; // 4 KiB at a time is way too slow
        let chunk_size_32 : u32 = 1 << 30; // 1 GiB
        assert!(chunk_size_32.is_power_of_two());
        let chunk_size : usize = chunk_size_32.try_into().map_err(|_| SparseBoxError(()))?; // lol 16 bit windows go brrr
        let total_size = (layout.size().saturating_sub(1)/chunk_size+1)*chunk_size; // round up to multiple of chunk_size

        let zeroed_chunk = FileMapping({
            let h = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, null_mut(), PAGE_READONLY, 0, chunk_size_32, null_mut()) };
            if h.is_null() { return Err(SparseBoxError::from_last_error()) }
            h
        });

        // FIXME: also consider using MEM_LARGE_PAGES ?
        let data = unsafe { VirtualAlloc2(null_mut(), null_mut(), total_size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, null_mut(), 0) };
        //debug_assert!(!data.is_null(), "VirtualAlloc2(nullptr, nullptr, {total_size}, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0) failed with GetLastError() == {err}", err=get_last_error());
        let data = NonNull::new(data).ok_or_else(SparseBoxError::from_last_error)?;
        // FIXME: `data` is leaked on future early bails

        for offset in (0 .. total_size).step_by(chunk_size) {
            let chunk_base = unsafe { data.as_ptr().cast::<u8>().add(offset).cast() };

            if offset + chunk_size < total_size { // VirtualFree will fail if we attempt to free the entire remaining placeholder (e.g. the last chunk)
                let success = unsafe { VirtualFree(chunk_base, chunk_size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) };
                assert!(success != 0, "VirtualFree({chunk_base:?}, {chunk_size}, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) failed with GetLastError() == {err}", err=get_last_error());
            }

            let _view = unsafe { MapViewOfFile3(zeroed_chunk.0, null_mut(), chunk_base, 0, chunk_size, MEM_REPLACE_PLACEHOLDER, PAGE_READONLY, null_mut(), 0) };
            assert!(!_view.is_null(), "MapViewOfFile3({zeroed_chunk:?}, nullptr, {chunk_base:?}, 0, {chunk_size}, MEM_REPLACE_PLACEHOLDER, PAGE_READ, nullptr, 0) failed with GetLastError() == {err}", err=get_last_error());
        }

        let data = unsafe { NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(data.as_ptr().cast(), len)) };

        Ok(SparseBox { data, chunk_size, total_size, zeroed_chunk })
    }
}

impl<T> SparseBox<[T]> {
    pub fn copy_from_slice_at(&mut self, start: usize, src: &[T]) where T : Copy {
        assert!(start < self.len());
        let end = start.checked_add(src.len()).expect("unable to write full range: usize::MAX overflows");
        assert!(end <= self.len());

        let chunk_size  = self.chunk_size;
        let chunk_mask  = chunk_size - 1;
        let byte_start  = (start * size_of::<T>()) & !chunk_mask;
        let byte_end    = (end * size_of::<T>()).saturating_add(chunk_mask) & !chunk_mask;
        for offset in (byte_start .. byte_end).step_by(chunk_size) {
            let chunk_base = unsafe { self.data.as_ptr().cast::<u8>().add(offset).cast() };

            let success = unsafe { UnmapViewOfFileEx(chunk_base, MEM_PRESERVE_PLACEHOLDER) };
            if success == 0 { continue } // XXX: assume we already committed that page

            let _commit = unsafe { VirtualAlloc2(null_mut(), chunk_base, chunk_size, MEM_COMMIT | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, null_mut(), 0) };
            assert!(!_commit.is_null(), "VirtualAlloc2(nullptr, {chunk_base:?}, {chunk_size}, MEM_COMMIT | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0) failed with GetLastError() == {err}", err=get_last_error());
        }

        let data = unsafe { self.data.as_mut() };
        data[start .. end].copy_from_slice(src);
    }
}

impl<T: ?Sized> Deref for SparseBox<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target { unsafe { self.data.as_ref() } }
}

// DO NOT IMPLEMENT: DerefMut
// As SparseBox<T> contains readonly zeroed pages, implementing DerefMut would be undefined behavior.
// Providing mut slices into known writeable ranges would be safe.
// FIXME: write doc tests enforcing compile_fail



#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)] pub struct SparseBoxError(());
impl SparseBoxError { fn from_last_error() -> Self { Self(()) } }
impl From<core::alloc::LayoutError> for SparseBoxError { fn from(_: core::alloc::LayoutError) -> Self { Self(()) } }
// ...



#[derive(Debug)] struct FileMapping(HANDLE);
impl Drop for FileMapping {
    fn drop(&mut self) {
        let success = unsafe { CloseHandle(self.0) };
        assert!(success != 0, "CloseHandle({:?}) failed with GetLastError() == {}", self.0, get_last_error());
    }
}



fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

fn get_system_info() -> SYSTEM_INFO {
    let mut info = unsafe { core::mem::zeroed() };
    let _ : () = unsafe { GetSystemInfo(&mut info) };
    info
}



// C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\winnt.h
const MEM_COALESCE_PLACEHOLDERS : u32 = 0x00000001;
const MEM_PRESERVE_PLACEHOLDER  : u32 = 0x00000002;
const MEM_REPLACE_PLACEHOLDER   : u32 = 0x00004000;
const MEM_RESERVE_PLACEHOLDER   : u32 = 0x00040000;
const MEM_LARGE_PAGES           : u32 = 0x20000000;
const MEM_4MB_PAGES             : u32 = 0x80000000;
const MEM_64K_PAGES             : u32 = MEM_LARGE_PAGES | MEM_PHYSICAL;

// C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\memoryapi.h
#[link(name = "onecore")] // MapViewOfFile3
extern "system" {
    // WINAPI
    fn VirtualAlloc2(
        Process:                HANDLE,                         // _In_opt_
        BaseAddress:            PVOID,                          // _In_opt_
        Size:                   SIZE_T,                         // _In_
        AllocationType:         ULONG,                          // _In_
        PageProtection:         ULONG,                          // _In_
        ExtendedParameters:     *mut MEM_EXTENDED_PARAMETER,    // _Inout_updates_opt_(ParameterCount)
        ParameterCount:         ULONG,                          // _In_
    ) -> PVOID; // _Ret_maybenull_ _Post_writable_byte_size_(Size)

    // WINBASEAPI
    fn MapViewOfFile3(
        FileMapping:            HANDLE,                         // _In_
        Process:                HANDLE,                         // _In_opt_
        BaseAddress:            PVOID,                          // _In_opt_
        Offset:                 ULONG64,                        // _In_
        ViewSize:               SIZE_T,                         // _In_
        AllocationType:         ULONG,                          // _In_
        PageProtection:         ULONG,                          // _In_
        ExtendedParameters:     *mut MEM_EXTENDED_PARAMETER,    // _Inout_updates_opt_(ParameterCount)
        ParameterCount:         ULONG,                          // _In_
    ) -> PVOID; // _Ret_maybenull_ __out_data_source(FILE)

    // WINBASEAPI
    fn VirtualAlloc2FromApp(
        Process:                HANDLE,                         // _In_opt_
        BaseAddress:            PVOID,                          // _In_opt_
        Size:                   SIZE_T,                         // _In_
        AllocationType:         ULONG,                          // _In_
        PageProtection:         ULONG,                          // _In_
        ExtendedParameters:     *mut MEM_EXTENDED_PARAMETER,    // _Inout_updates_opt_(ParameterCount)
        ParameterCount:         ULONG,                          // _In_
    ) -> PVOID; // _Ret_maybenull_ _Post_writable_byte_size_(Size)

    // WINBASEAPI
    fn MapViewOfFile3FromApp(
        FileMapping:            HANDLE,                         // _In_
        Process:                HANDLE,                         // _In_opt_
        BaseAddress:            PVOID,                          // _In_opt_
        Offset:                 ULONG64,                        // _In_
        ViewSize:               SIZE_T,                         // _In_
        AllocationType:         ULONG,                          // _In_
        PageProtection:         ULONG,                          // _In_
        ExtendedParameters:     *mut MEM_EXTENDED_PARAMETER,    // _Inout_updates_opt_(ParameterCount)
        ParameterCount:         ULONG,                          // _In_
    ) -> PVOID; // _Ret_maybenull_ __out_data_source(FILE)
}

// C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\winnt.h
const MEM_EXTENDED_PARAMETER_TYPE_BITS : u64 = 8;
#[derive(Clone, Copy, Default, Zeroable)] #[repr(C, align(8))] struct MEM_EXTENDED_PARAMETER {
    _Type_Reserved: DWORD64,
    pub u: MEM_EXTENDED_PARAMETER_u,
}
impl MEM_EXTENDED_PARAMETER {
    pub fn Type(&self) -> u64 { self._Type_Reserved & (1<<MEM_EXTENDED_PARAMETER_TYPE_BITS - 1) }
}
#[derive(Clone, Copy, Zeroable)] #[repr(C)] union MEM_EXTENDED_PARAMETER_u { // FIXME: is DECLSPEC_ALIGN(8) inherited?
    ULong64:    DWORD64,
    Pointer:    PVOID,
    Size:       SIZE_T,
    Handle:     HANDLE,
    ULong:      DWORD,
}
impl Default for MEM_EXTENDED_PARAMETER_u { fn default() -> Self { Zeroable::zeroed() } }

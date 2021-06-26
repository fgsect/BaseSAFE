extern crate capstone;

use std::{cell::RefCell, env, fs::File, io::{self, BufReader, Read}};

use flate2::read::GzDecoder;
use unicornafl::{
    unicorn_const::{uc_error, Arch, Mode, Permission},
    utils::*,
    RegisterARM,
};

type Unicorn<'a> = unicornafl::UnicornHandle<'a, RefCell<Heap>>;

fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    let f = File::open(filename)?;
    let mut bf = BufReader::new(f);
    let mut decoder = GzDecoder::new(&mut bf);
    //let modem_image = decoder.
    let mut buffer = vec![];
    decoder.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// find null terminated string in vec
///
/// # Safety
/// Data at utff8_src needs to be valid utf8
pub unsafe fn str_from_u8_nul_utf8_unchecked(utf8_src: &[u8]) -> &str {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len());
    ::std::str::from_utf8_unchecked(&utf8_src[0..nul_range_end])
}

fn align(size: u64) -> u64 {
    const ALIGNMENT: u64 = 0x1000;
    if size % ALIGNMENT == 0 {
        size
    } else {
        ((size / ALIGNMENT) + 1) * ALIGNMENT
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("Missing parameter <emulation_input> (@@ for AFL)");
        return;
    }

    const BASEBAND_PATH: &str = "./modem.bin.gz";

    // TODO: Check alignment
    const BASE_ADDR: u64 = 0x4000df40;
    const ENTRYPOINT: u64 = 0x414cf592 | 1;

    let modem_image = read_file(BASEBAND_PATH)
        .unwrap_or_else(|_| panic!("Could not read modem image: {}", BASEBAND_PATH));

    let modem_len = modem_image.len();
    let aligned_start = align(BASE_ADDR) - BASE_ADDR;
    let aligned_size = align(modem_len as u64 - aligned_start);

    let mut unicorn = init_emu_with_heap(Arch::ARM, Mode::THUMB, 1048576 * 20, 0x90000000, false)
        .expect("failed to create emulator instance");
    let mut emu = unicorn.borrow();

    emu.mem_map(0x0A000000, 0x1000000, Permission::READ | Permission::WRITE)
        .expect("failed to map input buffer");

    const STACK_SIZE: u32 = 0x1000 * 16;
    const STACK_ADDR: u32 = 0x7f000000;
    emu.mem_map(
        (STACK_ADDR - STACK_SIZE) as u64,
        STACK_SIZE as usize,
        Permission::READ | Permission::WRITE,
    )
    .expect("map stack failed");
    emu.reg_write(RegisterARM::SP as i32, STACK_ADDR as u64)
        .expect("failed write SP");

    #[cfg(debug_assertions)]
    println!(
        "Mapping {:#x} bytes (pagesize {:#x}) at addr {:#x}",
        modem_len, aligned_size, BASE_ADDR
    );
    emu.mem_map(
        BASE_ADDR + aligned_start,
        aligned_size as usize,
        Permission::READ | Permission::WRITE | Permission::EXEC,
    )
    .expect("failed to map EXEC pages");
    emu.mem_write(
        BASE_ADDR + aligned_start,
        &modem_image[aligned_start as usize..],
    )
    .expect("failed to write image");

    /*
        BEGIN FUNCTION HOOKS
    */

    // just returns
    let pass_func = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside pass_func");
    };

    // TODO: Find and replace shannon allocator
    let kal_get_buffer = |mut uc: Unicorn, _addr: u64, _size: u32| {
        let size = uc
            .reg_read(RegisterARM::R2 as i32)
            .expect("failed to read r2");
        let ptr = uc_alloc(&mut uc, size).expect("failed to alloc");

        uc.reg_write(RegisterARM::R0 as i32, ptr)
            .expect("failed to write new_buf_ptr to r0 inside kal_get_buffer");
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside kal_get_buffer");
    };

    // TODO: Find and replace shannon free method
    let kal_release_buffer = |mut uc: Unicorn, _addr: u64, _size: u32| {
        let usr_buf = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0");
        uc_free(&mut uc, usr_buf).expect("failed to free");

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside kal_release_buffer");
    };

    let memset = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        let s_ptr = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0");
        let c = uc
            .reg_read_i32(RegisterARM::R1 as i32)
            .expect("failed to read r1");
        let n = uc
            .reg_read(RegisterARM::R2 as i32)
            .expect("failed to read r2");
        let byte = c.to_be_bytes()[3];
        #[cfg(debug_assertions)]
        println!("[*] memset: addr {:#x}, val {}, len {}\n", s_ptr, byte, n);

        let buf = vec![byte; n as usize];
        uc.mem_write(s_ptr, &buf)
            .expect("failed to write inside memset");

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside memset");
    };

    // TODO: Find and replace memcpy
    let memcpy = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        let dest = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0");
        let src = uc
            .reg_read(RegisterARM::R1 as i32)
            .expect("failed to read r1");
        let len = uc
            .reg_read(RegisterARM::R2 as i32)
            .expect("failed to read r2");
        #[cfg(debug_assertions)]
        println!(
            "[*] memcpy: dest {:#x}, src {:#x}, len {}\n",
            dest, src, len
        );

        let mut buf = vec![0; len as usize];
        uc.mem_read(src, &mut buf)
            .expect("failed to read from src in memcpy");
        uc.mem_write(dest, &buf)
            .expect("failed to write to dest in memcpy");

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside memcpy");
    };

    #[cfg(debug_assertions)]
    {
        add_debug_prints_ARM(
            &mut emu,
            BASE_ADDR + aligned_start,
            BASE_ADDR + aligned_size - 1,
        );
        let regions = emu
            .mem_regions()
            .expect("failed to retrieve memory mappings");
        println!("Regions : {}", regions.len());

        for region in &regions {
            println!("{:#010x?}", region);
        }

        println!("heap: {:#010x?}", emu.get_data());
    }

    let place_input_callback = |uc: &mut Unicorn, afl_input: &mut [u8], _: i32| {
        if afl_input.len() > 1024 {
            false
        } else {
            println!("Placing input of len {}", afl_input.len());
            uc.mem_write(0x0A000000, &afl_input).unwrap();
            uc.reg_write(RegisterARM::R0 as i32, 0x0A000000).unwrap();
            uc.reg_write(RegisterARM::PC as i32, ENTRYPOINT | 1)
                .unwrap();
            true
        }
    };

    let crash_validation_callback =
        move |_uc: &mut Unicorn, result: uc_error, _input: &[u8], _: i32| result != uc_error::OK;

    // fuzz Shannon ASN
    set_pc(&mut emu, ENTRYPOINT).unwrap();
    let ret = emu.afl_fuzz(
        args[1].as_str(),
        place_input_callback,
        &[0x414cec98],
        crash_validation_callback,
        false,
        1,
    );

    match ret {
        Ok(_) => {}
        Err(e) => panic!("found non-ok unicorn exit: {:?}", e),
    }
}

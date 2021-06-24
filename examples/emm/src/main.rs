extern crate capstone;

use std::cell::RefCell;
use std::env;
use std::fs::File;
use std::io;
use std::io::Read;

use unicornafl::unicorn_const::{uc_error, Arch, Permission};
use unicornafl::utils::*;
use unicornafl::RegisterARM;

type Unicorn<'a> = unicornafl::UnicornHandle<'a, RefCell<Heap>>;

fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    let mut f = File::open(filename)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// find null terminated string in vec
///
/// # Safety
/// Should only be called with valid utf8
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
    let input_file = &args[1];

    const BASEBAND_PATH: &str = "../modem_raw.img";
    const BASE_ADDR: u64 = 0x0;

    let modem_image = read_file(BASEBAND_PATH)
        .unwrap_or_else(|_| panic!("Could not read modem image: {}", BASEBAND_PATH));
    let modem_len = modem_image.len() as u64;

    let aligned_size = align(modem_len);

    let mut unicorn = init_emu_with_heap(Arch::ARM, 1048576 * 20, 0x90000000, false)
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
    emu.reg_write(RegisterARM::SP as i32, STACK_ADDR as u64 - 0x24)
        .expect("failed write SP");

    #[cfg(debug_assertions)]
    println!(
        "Mapping {:#x} bytes (pagesize {:#x}) at addr {:#x}",
        modem_len, aligned_size, BASE_ADDR
    );
    emu.mem_map(
        BASE_ADDR,
        aligned_size as usize,
        Permission::READ | Permission::EXEC,
    )
    .expect("failed to map EXEC pages");
    emu.mem_write(BASE_ADDR, &modem_image)
        .expect("failed to write image");

    emu.mem_map(0x70055000_u64, 4096, Permission::READ | Permission::WRITE)
        .expect("failed to map map current task index");
    emu.mem_map(0xF7330000, 4096, Permission::READ | Permission::WRITE)
        .expect("failed to map active module id");
    emu.mem_map(0xF6D05000, 4096 * 3, Permission::READ | Permission::WRITE)
        .expect("failed to map segment for global RecvMsg objects");
    emu.mem_map(0xF6E3A000, 4096, Permission::READ | Permission::WRITE)
        .expect("failed to map area for mcd_unpack");

    /*
        BEGIN FUNCTION HOOKS
    */

    let msg_recv = |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        println!("[*] msg_recv_*q\n");

        let mut buf_len_raw: [u8; 4] = [0; 4];
        uc.mem_read(0x0A000000, &mut buf_len_raw)
            .expect("failed to read length of input buffer");
        let buf_len = u32::from_le_bytes(buf_len_raw);
        if buf_len < 4 {
            // return KAL_FALSE
            uc.reg_write(RegisterARM::R0 as i32, 0)
                .expect("failed to write return val inside msg_recv_*q");
        } else {
            // populate Inter Layer Message struct (on stack)
            let ilm_ptr = uc
                .reg_read(RegisterARM::R0 as i32)
                .expect("failed to read r0");
            uc.mem_write(ilm_ptr, b"\x00\x01")
                .expect("failed to prepare ilm_struct inside msg_recv_*q"); // src_mod_id
            uc.mem_write(ilm_ptr + 2, b"\xb5\x01")
                .expect("failed to prepare ilm_struct inside msg_recv_*q"); // dest_mod_id
            uc.mem_write(ilm_ptr + 4, b"\x00\x00")
                .expect("failed to prepare ilm_struct inside msg_recv_*q"); // sap_id
                                                                            // msg_id
            uc.mem_write(ilm_ptr + 6, b"\x0c\x55")
                .expect("failed to prepare ilm_struct inside msg_recv_*q"); // rcv_attach_accept_ind

            // construct local_para_struct
            let local_para_ptr = uc_alloc(&mut uc, 4 + 4 + 4).expect("failed to alloc");
            uc.mem_write(local_para_ptr, b"\x01")
                .expect("failed to write local_para->ref_count");
            // size = header + length_u32 + pdu_ptr
            uc.mem_write(local_para_ptr + 2, &((4 + 4 + 4) as u16).to_le_bytes())
                .expect("failed to write local_para->msg_len");
            uc.mem_write(local_para_ptr + 4, &((buf_len as u32).to_le_bytes()))
                .expect("failed to write local_para->payload");
            uc.mem_write(local_para_ptr + 8, &((0x0A000008_u32).to_le_bytes()))
                .expect("failed to write local_para->payload");

            uc.mem_write(ilm_ptr + 8, &((local_para_ptr as u32).to_le_bytes()))
                .expect("failed to prepare ilm_struct->local_para_ptr inside msg_recv_*q");

            let null_ptr: [u8; 4] = [0; 4];
            uc.mem_write(ilm_ptr + 12, &null_ptr)
                .expect("failed to prepare ilm_struct->peer_buff_ptr inside msg_recv_*q");

            // return KAL_TRUE
            uc.reg_write(RegisterARM::R0 as i32, 1)
                .expect("failed to write return val inside msg_recv_*q");
        }

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside msg_recv_*q");
    };

    let pass_func = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside pass_func");
    };

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

    let free_int_buff = |mut uc: Unicorn, _addr: u64, _size: u32| {
        let struct_ptr = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0"); // pdu (protocol data unit) or local_para
        if struct_ptr != 0 {
            let mut ref_count: [u8; 1] = [0];
            uc.mem_read(struct_ptr + 2, &mut ref_count)
                .expect("failed to read struct->ref_count inside free_int_*_buff");
            ref_count[0] -= 1;
            if ref_count[0] == 0 {
                uc_free(&mut uc, struct_ptr as u64).expect("failed to free");
            } else {
                uc.mem_write(struct_ptr + 2, &ref_count)
                    .expect("failed to write ref_count back to pdu inside free_int_*_buff");
            }
        }

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside free_int_*_buff");
    };

    let free_ctrl_buffer_ext = |mut uc: Unicorn, _addr: u64, _size: u32| {
        let buff_ptr = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0");

        #[cfg(debug_assertions)]
        {
            let file_name_ptr = uc
                .reg_read(RegisterARM::R1 as i32)
                .expect("failed to read r1");
            let mut file_name_buf = vec![0; 64];
            uc.mem_read(file_name_ptr, &mut file_name_buf)
                .expect("failed to read file_name in free_ctrl_buffer_ext");
            let line = uc
                .reg_read(RegisterARM::R2 as i32)
                .expect("failed to read r2");
            unsafe {
                let file_name = str_from_u8_nul_utf8_unchecked(&file_name_buf);
                println!(
                    "[*] free_ctrl_buffer_ext: addr {:#010x}; {}:{}\n",
                    buff_ptr, file_name, line
                );
            }
        }

        uc_free(&mut uc, buff_ptr).expect("failed to free");
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside free_ctrl_buffer_ext");
    };

    let get_int_ctrl_buffer = |mut uc: Unicorn, _addr: u64, _size: u32| {
        let size = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0");
        let file_name_ptr = uc
            .reg_read(RegisterARM::R1 as i32)
            .expect("failed to read r1");

        let mut file_name_buf = vec![0; 64];
        uc.mem_read(file_name_ptr, &mut file_name_buf)
            .expect("failed to read file_name in get_int_ctrl_buffer");
        #[cfg(debug_assertions)]
        {
            let line = uc
                .reg_read(RegisterARM::R2 as i32)
                .expect("failed to read r2");
            unsafe {
                let file_name = str_from_u8_nul_utf8_unchecked(&file_name_buf);
                println!(
                    "[*] get_int_ctrl_buffer: size {}; {}:{}\n",
                    size, file_name, line
                );
            }
        }

        let new_buf_ptr = uc_alloc(&mut uc, size).expect("failed to alloc");
        uc.reg_write(RegisterARM::R0 as i32, new_buf_ptr)
            .expect("failed to write new_buf_ptr to r0 in get_int_ctrl_buffer");

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside get_int_ctrl_buffer");
    };

    let msg_send = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        println!("[*] msg_send\n");
        uc.reg_write(RegisterARM::R0 as i32, 1)
            .expect("failed to write ret val inside msg_send");
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside msg_send");
    };

    let kal_assert_fail_ext = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        println!("[*] kal_assert_fail_ext\n");
        uc.emu_stop().expect("failed to exit");
    };

    let kal_fatal_error_handler_int = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        {
            let r0 = uc
                .reg_read(RegisterARM::R0 as i32)
                .expect("failed to read r0");
            let r1 = uc
                .reg_read(RegisterARM::R1 as i32)
                .expect("failed to read r1");
            let lr = uc
                .reg_read(RegisterARM::LR as i32)
                .expect("failed to read lr");
            println!("[*] kal_fatal_error_handler_int:\n[!] FATAL ERROR coming from {:#010x}: error_code {}, os_error_code {}\n", lr, r0, r1);
        }

        uc.emu_stop().expect("failed to exit");
    };

    let destroy_int_ilm = |mut uc: Unicorn, _addr: u64, _size: u32| {
        let ilm_ptr = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0");
        let mut local_para_ptr: [u8; 4] = [0; 4];
        uc.mem_read(ilm_ptr + 8, &mut local_para_ptr)
            .expect("failed to read local_para_ptr in destroy_int_ilm");
        let mut peer_buff_ptr: [u8; 4] = [0; 4];
        uc.mem_read(ilm_ptr + 12, &mut peer_buff_ptr)
            .expect("failed to read peer_buff_ptr in destroy_int_ilm");

        let file_name_ptr = uc
            .reg_read(RegisterARM::R1 as i32)
            .expect("failed to read r1");
        let mut file_name_buf = vec![0; 64];
        uc.mem_read(file_name_ptr, &mut file_name_buf)
            .expect("failed to read file_name in destroy_int_ilm");

        #[cfg(debug_assertions)]
        {
            let line = uc
                .reg_read(RegisterARM::R2 as i32)
                .expect("failed to read r2");
            unsafe {
                let file_name = str_from_u8_nul_utf8_unchecked(&file_name_buf);
                println!(
                    "[*] destroy_int_ilm: ptr {}; {}:{}\n",
                    ilm_ptr, file_name, line
                );
            }
        }

        uc_free(&mut uc, u32::from_le_bytes(local_para_ptr) as u64).expect("failed to free");
        uc_free(&mut uc, u32::from_le_bytes(peer_buff_ptr) as u64).expect("failed to free");

        let null_ptr: [u8; 4] = [0; 4];
        uc.mem_write(ilm_ptr + 8, &null_ptr)
            .expect("failed to null local_para_ptr in destroy_int_ilm");
        uc.mem_write(ilm_ptr + 12, &null_ptr)
            .expect("failed to null peer_buff_ptr in destroy_int_ilm");

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside destroy_int_ilm");
    };

    let dhl_trace = |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        {
            let r0 = uc
                .reg_read(RegisterARM::R0 as i32)
                .expect("failed to read r0"); // trc_class
            let r2 = uc
                .reg_read(RegisterARM::R2 as i32)
                .expect("failed to read r2"); // msg_index
            println!("[*] dhl_trace: TRACE_CLASS {}, MSG_INDEX {}\n", r0, r2);
        }
        uc.reg_write(RegisterARM::PC as i32, BASE_ADDR + 0x00119bcb)
            .expect("failed to write pc inside dhl_trace");
    };

    let cemm_int_state8get_state_ev = |mut uc: Unicorn, _addr: u64, _size: u32| {
        uc.reg_write(RegisterARM::R0 as i32, 0x4)
            .expect("failed to write pc inside CEmmIntState8getStateEv");
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside CEmmIntState8getStateEv");
    };

    let mcd_unpack = |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        println!("[*] mcd_unpack\n");

        let mut buf_len_raw: [u8; 4] = [0; 4];
        uc.mem_read(0x0A000000, &mut buf_len_raw)
            .expect("failed to read length of input buffer");
        let buf_len = u32::from_le_bytes(buf_len_raw);
        if (8..=255).contains(&buf_len) {
            let new_buf_addr = uc_alloc(&mut uc, buf_len as u64).expect("failed to alloc");
            let mut new_buf = vec![0; buf_len as usize];
            uc.mem_read(0x0A000008, &mut new_buf)
                .expect("failed to read input buf");
            uc.mem_write(new_buf_addr, &new_buf)
                .expect("failed to write input buf into newly allocated mem");

            let dest = uc
                .reg_read(RegisterARM::R1 as i32)
                .expect("failed to read r1");
            uc.mem_write(dest + 0x05, b"\x01")
                .expect("failed to write buf to dest");
            uc.mem_write(dest + 0x08, b"\x07")
                .expect("failed to write buf to dest");
            uc.mem_write(dest + 0x40, b"\x01")
                .expect("failed to write buf to dest");
            uc.mem_write(dest + 0x41, &(buf_len as u8).to_le_bytes())
                .expect("failed to write buf to dest");
            uc.mem_write(dest + 0x44, &(new_buf_addr).to_le_bytes())
                .expect("failed to write buf to dest");
            uc.reg_write(RegisterARM::R0 as i32, (buf_len) as u64)
                .expect("failed to write return val inside mcd_unpack");
        } else {
            uc.reg_write(RegisterARM::R0 as i32, 0xffffffff)
                .expect("failed to write return val inside mcd_unpack");
        }
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write back PC");
    };

    let init = |mut uc: Unicorn, _addr: u64, _size: u32| {
        uc.reg_write(RegisterARM::R0 as i32, 0xF6D06F5C)
            .expect("failed to write _this_ reference to r0 for decodeCheckAttachAccept");
        let internal_buf = uc_alloc(&mut uc, 0x47c).expect("failed to alloc");
        uc.reg_write(RegisterARM::R1 as i32, internal_buf)
            .expect("failed to write internal_buf pointer to r1 for decodeCheckAttachAccept");
        uc.reg_write(RegisterARM::R2 as i32, 0x0)
            .expect("failed to write pdu reference to r2 for decodeCheckAttachAccept"); // we don't need the pdu
        uc.reg_write(RegisterARM::R3 as i32, 0x0)
            .expect("failed to write pdu size reference to r3 for decodeCheckAttachAccept"); // hence we don't need the size
        let decoded_buf = uc_alloc(&mut uc, 0x800).expect("failed to alloc");
        uc.reg_write(RegisterARM::R4 as i32, decoded_buf)
            .expect("failed to write decoded_buf pointer to r4 for decodeCheckAttachAccept");
        uc.reg_write(RegisterARM::R5 as i32, 0x800)
            .expect("failed to write decode_buff size reference to r5 for decodeCheckAttachAccept");
    };

    #[cfg(debug_assertions)]
    {
        add_debug_prints_ARM(&mut emu, 0x0, aligned_size - 1);
        println!("heap: {:#x?}", emu.get_data());
    }

    macro_rules! hook {
        ($addr:expr, $func:expr) => {
            emu.add_code_hook($addr, $addr, Box::new($func))
                .expect(&format!("failed to set {} hook", stringify!($func)));
        };
        ($addr:expr, $func:expr, $opt_name:expr) => {
            emu.add_code_hook($addr, $addr, Box::new($func))
                .expect(&format!("failed to set {} hook", $opt_name));
        };
    }

    hook!(0x3b4fc4, msg_recv, "msg_receive_extq");
    hook!(0x3b5010, msg_recv, "msg_receive_intq");
    hook!(0x00119b68, dhl_trace);
    hook!(0x00119768, pass_func, "dhl_peer_trace");
    hook!(0x003b28a0, pass_func, "stack_get_active_module_id");
    hook!(0x003b5478, kal_get_buffer);
    hook!(0x003b5560, kal_release_buffer);
    hook!(0x003fa4d4, memcpy);
    hook!(0x003fb818, memcpy);
    hook!(0x003fad94, memset);
    hook!(0x003b7c18, get_int_ctrl_buffer);
    hook!(0x003b7c92, free_ctrl_buffer_ext);
    hook!(0x003b4c08, free_int_buff, "free_int_peer_buff");
    hook!(0x003b4c50, free_int_buff, "free_int_local_para");
    hook!(0x003b4e5c, msg_send);
    hook!(0x003fb508, kal_assert_fail_ext);
    hook!(0x003fb570, kal_assert_fail_ext);
    hook!(0x003b3fc0, kal_fatal_error_handler_int);
    hook!(0x003b4e56, destroy_int_ilm);
    hook!(0x001b6d44, cemm_int_state8get_state_ev);
    hook!(0x001d6d20, pass_func, "_ZN7CEmmReg19sndAcceptFailureIndEv");
    hook!(0x001c527c, pass_func, "_ZN7CEmmReg16msgEndCommonProcEv");
    hook!(0x001e6a30, init);
    hook!(0x00489dfc, mcd_unpack);

    let place_input_callback = |mut uc: Unicorn, afl_input: &mut [u8], _: i32| {
        uc.mem_write(0x0A000000, &(afl_input.len() as u32).to_le_bytes())
            .expect("failed to write input_size");
        uc.mem_write(0x0A000000 + 8, &afl_input)
            .expect("failed to write input buffer");
        true
    };

    let crash_validation_callback =
        |_uc: Unicorn, result: uc_error, _input: &[u8], _: i32| result != uc_error::OK;

    // fuzz decoder for ATTACH ACCEPT messages
    emu.emu_start(0x001e6a31, 0x001e6c82, 0, 1)
        .expect("failed to kick off"); // start at offset 1 to run in thumb mode
    let ret = emu.afl_fuzz(
        input_file,
        place_input_callback,
        &[0x001e6c82],
        crash_validation_callback,
        false,
        1,
    );

    match ret {
        Ok(_) => {}
        Err(e) => panic!("found non-ok unicorn exit: {:?}", e),
    }
}

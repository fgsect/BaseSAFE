extern crate capstone;
extern crate libc;

use std::cell::RefCell;
use std::env;
use std::fs::File;
use std::io;
use std::io::Read;

use unicornafl::{
    unicorn_const::{Arch, Permission},
    utils::*,
    RegisterARM,
};

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
    let mut mode = String::from("explore");
    if args.len() == 1 {
        println!("Missing parameter <emulation_input> (@@ for AFL)");
        return;
    } else if args.len() == 3 {
        mode = args[2].to_ascii_uppercase();
    }
    let arg = Box::new(args[1].to_owned());
    let input_file = Box::leak(arg);

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
    emu.reg_write(RegisterARM::SP as i32, STACK_ADDR as u64)
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

    emu.mem_map(0x70055400, 1024, Permission::READ | Permission::WRITE)
        .expect("failed to map DAT_70055500");
    emu.mem_map(0xF5F7F800, 2048, Permission::READ | Permission::WRITE)
        .expect("failed to map main_function_tbl");
    emu.mem_map(0xF731C800, 2048, Permission::READ | Permission::WRITE)
        .expect("failed to map ASN_BLOCK_FREE_NUM");
    emu.mem_write(0xF731CDF4, b"\x01\x00\x00\x01")
        .expect("failed to write ASN_BLOCK_FREE_NUM");

    /*
        BEGIN FUNCTION HOOKS
    */

    let msg_recv = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        println!("[*] msg_recv_*q\n");

        let mut buf_len_raw = [0_u8; 2];
        uc.mem_read(0x0A000000, &mut buf_len_raw)
            .expect("failed to read length of input buffer");
        let buf_len = u16::from_le_bytes(buf_len_raw) - 1;
        if buf_len < 4 || buf_len == 65535 {
            // return KAL_FALSE
            uc.reg_write(RegisterARM::R0 as i32, 0)
                .expect("failed to write return val inside msg_recv_*q");
        } else {
            // populate Inter Layer Message struct (on stack)
            let ilm_ptr = uc
                .reg_read(RegisterARM::R0 as i32)
                .expect("failed to read r0");
            uc.mem_write(ilm_ptr, b"\x00\x01")
                .expect("failed to write src_mod_id inside msg_recv_*q");
            uc.mem_write(ilm_ptr + 2, b"\x01\x00")
                .expect("failed to write dest_mod_id inside msg_recv_*q");
            uc.mem_write(ilm_ptr + 4, b"\x00\x00")
                .expect("failed to write sap_id inside msg_recv_*q");

            let mut msg_id = 255_u16;
            if mode == "explore" {
                let mut msg_id_raw = [0_u8; 1];
                uc.mem_read(0x0A000008, &mut msg_id_raw)
                    .expect("failed to read first input byte for msg_id");
                msg_id = msg_id_raw[0] as u16 % 5;
            }

            let null_ptr = [0_u8; 4];

            if msg_id == 4 {
                // DL_DCCH with pdu in peer_buff
                msg_id = 0x50ab;

                let mut free_header_space = [0_u8; 1];
                let mut free_tail_space = [0_u8; 1];
                uc.mem_read(0x0A000009, &mut free_header_space)
                    .expect("failed read free_header_space");
                uc.mem_read(0x0A00000A, &mut free_tail_space)
                    .expect("failed read free_tail_space");
                let pb_size = 8 + free_header_space[0] as u32 + buf_len as u32 - 2
                    + free_tail_space[0] as u32;
                let peer_buff_ptr = uc_alloc(&mut uc, pb_size as u64).expect("failed to alloc");
                uc.mem_write(peer_buff_ptr + 2, b"\x01")
                    .expect("failed to write peer_buff->ref_count");

                let mut new_buf = vec![0; buf_len as usize - 2];
                uc.mem_read(0x0A00000B, &mut new_buf)
                    .expect("failed to read mapped input buffer");

                uc.mem_write(peer_buff_ptr, &((buf_len as u16 - 2).to_le_bytes()))
                    .expect("failed to write peer_buff_buf->pdu_len");
                uc.mem_write(
                    peer_buff_ptr + 4,
                    &((free_header_space[0] as u16).to_le_bytes()),
                )
                .expect("failed to write peer_buff_buf->free_header_space");
                uc.mem_write(
                    peer_buff_ptr + 6,
                    &((free_tail_space[0] as u16).to_le_bytes()),
                )
                .expect("failed to write peer_buff_buf->free_tail_space");
                uc.mem_write(peer_buff_ptr + 8 + free_header_space[0] as u64, &new_buf)
                    .expect("failed to write peer_buff_buf->payload");

                uc.mem_write(ilm_ptr + 12, &((peer_buff_ptr as u32).to_le_bytes()))
                    .expect("failed to prepare ilm_struct->peer_buff_ptr inside msg_recv_*q");
                uc.mem_write(ilm_ptr + 8, &null_ptr)
                    .expect("failed to prepare ilm_struct->local_para_ptr inside msg_recv_*q");
            } else {
                // prepare actual payload buffer
                let pdu_ptr = uc_alloc(&mut uc, buf_len as u64).expect("failed to alloc");
                let mut new_buf = vec![0; buf_len as _];
                uc.mem_read(0x0A000009, &mut new_buf)
                    .expect("failed to read mapped input buffer");
                uc.mem_write(pdu_ptr, &new_buf)
                    .expect("failed to write input buffer to allocated chunk");

                let qbm_ptr = uc_alloc(&mut uc, 16_u64).expect("failed to alloc");
                // prepare pointers to incoming buffer: char** at local_para + 8 + 8; length at local_para + 8 + 0xc
                uc.mem_write(qbm_ptr + 8, &((pdu_ptr).to_le_bytes()))
                    .expect("failed to write char** ptr + 8");
                uc.mem_write(qbm_ptr + 0xc, &((buf_len as u16).to_le_bytes()))
                    .expect("failed to write ushort* ptr + 12");
                // size = header + offset_0 + offset_1 + payload_ptr + len_ptr
                let local_para_ptr =
                    uc_alloc(&mut uc, 4 + 0x10 + 8 + 4 + 4).expect("failed to alloc");
                uc.mem_write(local_para_ptr, b"\x01")
                    .expect("failed to write local_para->ref_count");
                uc.mem_write(
                    local_para_ptr + 2,
                    &((4 + 0x10 + 8 + 4 + 4) as u16).to_le_bytes(),
                )
                .expect("failed to write local_para->msg_len");

                if msg_id == 0 || mode.to_ascii_uppercase() == "PCCH" {
                    msg_id = 0x5082;
                    uc.mem_write(local_para_ptr + 8, &((qbm_ptr as u32).to_le_bytes()))
                        .expect("failed to write local_para->payload");
                } else if msg_id == 1 || mode.to_ascii_uppercase() == "BCCH_DL_SCH" {
                    msg_id = 0x5078;
                    uc.mem_write(local_para_ptr + 8, &((qbm_ptr as u32).to_le_bytes()))
                        .expect("failed to write local_para->payload");
                } else if msg_id == 2 || mode.to_ascii_uppercase() == "DL_CCCH" {
                    msg_id = 0x5086;
                    uc.mem_write(local_para_ptr + 4, &((qbm_ptr as u32).to_le_bytes()))
                        .expect("failed to write local_para->payload");
                } else if msg_id == 3 || mode.to_ascii_uppercase() == "DL_DCCH" {
                    msg_id = 0x5094;
                    uc.mem_write(local_para_ptr + 0x10, &((qbm_ptr as u32).to_le_bytes()))
                        .expect("failed to write local_para->payload");
                }

                uc.mem_write(ilm_ptr + 8, &((local_para_ptr as u32).to_le_bytes()))
                    .expect("failed to prepare ilm_struct->local_para_ptr inside msg_recv_*q");
                uc.mem_write(ilm_ptr + 12, &null_ptr)
                    .expect("failed to prepare ilm_struct->peer_buff_ptr inside msg_recv_*q");
            }

            if msg_id != 255 {
                // return KAL_TRUE
                uc.mem_write(ilm_ptr + 6, &(msg_id as u16).to_le_bytes())
                    .expect("failed to write msg_id inside msg_recv_*q");
                uc.reg_write(RegisterARM::R0 as i32, 1)
                    .expect("failed to write return val inside msg_recv_*q");
            } else {
                uc.reg_write(RegisterARM::R0 as i32, 0)
                    .expect("failed to write return val inside msg_recv_*q");
            }
        }

        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside msg_recv_*q");
    };

    let errc_evth_dump_reserve_queue = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        #[cfg(debug_assertions)]
        println!("[*] errc_evth_dump_reserve_queue\n");
        uc.reg_write(RegisterARM::PC as i32, BASE_ADDR + 0x001fe313)
            .expect("failed to write pc inside errc_evth_dump_reserve_queue");
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
            if _addr == 0x003b7c92 {
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
                        "[*] free_ctrl_buffer_ext: addr {}; {}:{}\n",
                        buff_ptr, file_name, line
                    );
                }
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

    let errc_spv_is_errc_gemini_suspended = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        uc.reg_write(RegisterARM::R0 as i32, 0)
            .expect("failed to write ret val inside is_errc_gemini_suspended");
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside is_errc_gemini_suspended");
    };

    let errc_spv_get_rrc_state = move |mut uc: Unicorn, _addr: u64, _size: u32| {
        // typedef enum
        // {
        //     RRC_STATE_INACTIVE,
        //     RRC_STATE_IDLE,
        //     RRC_STATE_CELL_DCH,
        //     RRC_STATE_CELL_FACH,
        //     RRC_STATE_CELL_PCH,
        //     RRC_STATE_URA_PCH
        // } rrc_state_enum;

        uc.reg_write(RegisterARM::R0 as i32, 1)
            .expect("failed to write ret val inside get_rrc_state");
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        uc.reg_write(RegisterARM::PC as i32, lr)
            .expect("failed to write pc inside get_rrc_state");
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
        let mut local_para_ptr = [0_u8; 4];
        uc.mem_read(ilm_ptr + 8, &mut local_para_ptr)
            .expect("failed to read local_para_ptr in destroy_int_ilm");
        let mut peer_buff_ptr = [0_u8; 4];
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
                    "[*] destroy_int_ilm: ptr {:#010x}; {}:{}\n",
                    ilm_ptr, file_name, line
                );
            }
        }

        uc_free(&mut uc, u32::from_le_bytes(local_para_ptr) as u64).expect("failed to free");
        uc_free(&mut uc, u32::from_le_bytes(peer_buff_ptr) as u64).expect("failed to free");

        let null_ptr: [u8; 4] = [0; 4_usize];
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

    let skip_internal_queue_loop = |mut uc: Unicorn, _addr: u64, _size: u32| {
        uc.reg_write(RegisterARM::PC as i32, BASE_ADDR + 0x001ff106)
            .expect("failed to write pc inside skip_internal_queue_loop");
    };

    macro_rules! hook {
        ($addr:expr, $func:expr) => {
            emu.add_code_hook($addr, $addr, $func)
                .expect(&format!("failed to set {} hook", stringify!($func)));
        };
        ($addr:expr, $func:expr, $opt_name:expr) => {
            emu.add_code_hook($addr, $addr, $func)
                .expect(&format!("failed to set {} hook", $opt_name));
        };
    }

    hook!(0x3b4fc4, msg_recv, "msg_receive_extq");
    hook!(0x3b5010, pass_func, "msg_receive_intq");
    hook!(0x00119b68, dhl_trace);
    hook!(0x00119768, pass_func, "dhl_peer_trace");
    hook!(0x001fe2f0, errc_evth_dump_reserve_queue);
    hook!(0x001f3d8c, pass_func, "errc_evth_com_timer_expiry_hdlr");
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
    hook!(0x00219798, errc_spv_get_rrc_state);
    hook!(0x002185fc, errc_spv_is_errc_gemini_suspended);
    hook!(0x003fb508, kal_assert_fail_ext);
    hook!(0x003fb570, kal_assert_fail_ext);
    hook!(0x003b3fc0, kal_fatal_error_handler_int);
    hook!(0x003b4e56, destroy_int_ilm);
    hook!(0x004d17e0, free_ctrl_buffer_ext, "qbm_free_one");
    hook!(
        0x001f4368,
        pass_func,
        "errc_com_calculate_procedure_delay_start"
    );
    hook!(0x001f3994, pass_func, "errc_com_stop_timer");
    hook!(0x001f3860, pass_func, "errc_com_start_timer");
    hook!(0x001f4d90, pass_func, "errc_conn_any_get_sec_sts");
    hook!(0x0021ee74, pass_func, "errc_sys_evth_trace_peer");
    hook!(0x0022c0b0, pass_func, "errc_cel_evth_trace_peer");
    hook!(0x003fae40, pass_func);
    hook!(0x006c4d20, memset, "asnMemSet");
    hook!(0x001ff0bc, skip_internal_queue_loop);

    #[cfg(debug_assertions)]
    {
        add_debug_prints_ARM(&mut emu, 0x0, aligned_size - 1);
        let regions = emu
            .mem_regions()
            .expect("failed to retrieve memory mappings");
        println!("Regions : {}", regions.len());

        for region in &regions {
            println!("{:#010x?}", region);
        }

        println!("heap: {:#010x?}", emu.get_data());
    }

    let place_input_callback = |mut uc: Unicorn, afl_input: &mut [u8], _: i32| {
        if afl_input.len() > 4096 {
            false
        } else {
            uc.mem_write(0x0A000000, &(afl_input.len() as u16).to_le_bytes())
                .expect("failed to write input_size");
            uc.mem_write(0x0A000000 + 8, &afl_input)
                .expect("failed to write input buffer");
            true
        }
    };

    let crash_validation_callback =
        move |_uc: Unicorn, result: unicornafl::unicorn_const::uc_error, _input: &[u8], _: i32| {
            result != unicornafl::unicorn_const::uc_error::OK
        };

    // fuzz ASN.1 decoders in ERRC handler
    emu.emu_start(0x1fe741, 0x001ff106, 0, 1)
        .expect("failed to kick off emulation"); // start at offset 1 to run in thumb mode
    let ret = emu.afl_fuzz(
        input_file,
        place_input_callback,
        &[0x001ff106, 0x001ff0aa],
        crash_validation_callback,
        false,
        1,
    );

    match ret {
        Ok(_) => {}
        Err(e) => panic!("found non-ok unicorn exit: {:?}", e),
    }
}

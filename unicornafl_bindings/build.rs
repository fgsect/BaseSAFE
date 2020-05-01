use std::{
    env,
    process::Command,
};

use build_helper::rustc::{link_lib, link_search};

fn main() {
    println!("cargo:rerun-if-changed=unicornafl");
    let out_dir = env::var("OUT_DIR").unwrap();
    let unicorn = "libunicornafl.a";
        let _ = Command::new("cp")
            .current_dir("../AFLplusplus/unicorn_mode/unicornafl")
            .arg(&unicorn)
            .arg(&out_dir)
            .status()
            .unwrap();
    link_search(
        Some(build_helper::SearchKind::Native),
            build_helper::out_dir());
    link_lib(Some(build_helper::LibKind::Static), "unicornafl");
}

fn fail(s: &str) -> ! {
    panic!("\n{}\n\nbuild script failed, must exit now", s)
}

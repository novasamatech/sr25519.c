use std::path::Path;

extern crate cbindgen;
use cbindgen::generate;

fn main() {
    generate(Path::new(".")).unwrap().write_to_file(Path::new("./Generated/sr25519/sr25519.h"));
}
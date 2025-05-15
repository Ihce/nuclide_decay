// Minimal build script - no special actions needed for PyO3
fn main() {
    println!("cargo:rerun-if-changed=src/");
}

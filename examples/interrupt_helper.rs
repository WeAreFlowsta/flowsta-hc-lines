//! The interrupt helper as a program of its own: what an app's `main` does
//! in its first line. `interrupt_helper --hc-lines-interrupt <pid>` raises
//! Ctrl-C in that process's console (Windows) and exits 0; anything else
//! prints this and exits 2. The Windows stop test uses it.
fn main() {
    flowsta_hc_lines::process::interrupt_helper_or_continue();
    eprintln!("usage: interrupt_helper {} <pid>", flowsta_hc_lines::process::INTERRUPT_HELPER_ARG);
    std::process::exit(2);
}

//! Administrative companion for installing and managing rust-xhttp.

#[path = "../management.rs"]
mod management;

fn main() {
    if let Err(error) = management::run() {
        eprintln!("rust-xhttpctl: {error}");
        std::process::exit(1);
    }
}

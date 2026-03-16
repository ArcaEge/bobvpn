//! An example of reading from tun
//!
//! It creates a tun device, sets it up (using shell commands) for local use and then prints the
//! raw data of the packets that arrive.
//!
//! You really do want better error handling than all these unwraps.
extern crate tun_tap;

use std::{env, error::Error, process::Command};
use tun_tap::{Iface, Mode};
mod client;
mod device;
mod peer;
mod server;

enum RunType {
    Server(Iface),
    Client(Iface, String),
}

impl RunType {
    fn run(&self) -> ! {
        match self {
            Self::Server(iface) => {
                server::run(iface);
            }

            Self::Client(iface, address) => {
                cmd(
                    "ip",
                    &[
                        "route",
                        "add",
                        "default",
                        "via",
                        "10.107.1.3",
                        "dev",
                        iface.name(),
                    ],
                );

                client::run(iface, address);
            }
        }
    }
}

/// Run a shell command. Panic if it fails in any way.
fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new(cmd)
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execute {}", cmd);
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    println!("args: {:?}", args);

    // Create the tun interface.
    let iface = Iface::new("tun%d", Mode::Tun).unwrap();
    eprintln!("Iface: {:?}", iface);

    // Configure the local (kernel) endpoint.
    cmd("ip", &["addr", "add", "dev", iface.name(), "10.107.1.2/24"]);
    cmd("ip", &["link", "set", "up", "dev", iface.name()]);
    cmd("ip", &["link", "set", "dev", iface.name(), "mtu", "1280"]);

    println!("Created interface {}", iface.name());

    let run_type = match args.get(1) {
        Some(string) => match string.as_str() {
            "client" => RunType::Client(
                iface,
                args.get(2)
                    .expect("no address string")
                    .clone(),
            ),
            "server" => RunType::Server(iface),
            _ => panic!("idiot"),
        },
        _ => panic!("must specify client or server"),
    };

    run_type.run();
}

use base32;
use clap::Parser;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use std::io::{self, Write};
use std::process;
use std::time;

/// A Time-Based One-Time Password (TOTP) generator CLI
#[derive(Parser)]
struct Args {
    /// The Base32-encoded secret key (defaults to stdin)
    base32_secret: Option<String>,

    /// The time step in seconds
    #[arg(short, long, default_value_t = 30)]
    interval: u64,

    /// The Unix time form which to start counting steps
    #[arg(short, long, default_value_t = 0)]
    epoch: u64,

    /// The number of digits in the TOTP code
    #[arg(short, long, default_value_t = 6)]
    digits: u32,
}

fn main() {
    let args = Args::parse();

    let base32_secret = args
        .base32_secret
        .unwrap_or_else(|| stdin().unwrap_or_else(|s| error(s)));

    match totp(&base32_secret, args.digits, args.epoch, args.interval) {
        Ok(code) => println!("{:0digits$}", code, digits = args.digits as usize),
        Err(err) => error(err.to_string().as_ref()),
    };
}

fn totp(secret: &str, digits: u32, epoch: u64, interval: u64) -> Result<u64, &'static str> {
    let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
        .ok_or("Invalid base32")?;
    let mut hmac: Hmac<Sha1> =
        Mac::new_from_slice(&secret_bytes).expect("HMAC should take any length");
    hmac.update(
        &((time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            - epoch)
            / interval)
            .to_be_bytes(),
    );
    let result = hmac.finalize().into_bytes();
    let offset = (result[19] & 0b1111) as usize;
    Ok(
        (u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) as u64
            & 0b1111111111111111111111111111111)
            % 10u64.pow(digits),
    )
}

fn stdin() -> Result<String, &'static str> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            let input: String = input.trim().to_string();
            Ok(input)
        }
        Err(_) => return Err("error reading stdin"),
    }
}

fn error(err: &str) -> ! {
    writeln!(&mut ::std::io::stderr(), "error: {}, try --help", err).unwrap();
    process::exit(1);
}

use base32;
use clap::Parser;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use std::io;
use std::process;
use std::time;

/// A Time-Based One-Time Password (TOTP) generator
///
/// To read from stdin: `echo <BASE32_SECRET> | totp`
#[derive(Parser)]
struct Args {
    /// The Base32-encoded secret key (defaults to stdin)
    base32_secret: Option<String>,

    /// The time step in seconds (the token period)
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
        .unwrap_or_else(|| read_line_from_stdin().unwrap_or_else(|s| print_error_and_exit(s)))
        .to_ascii_uppercase();

    match totp(&base32_secret, args.digits, args.epoch, args.interval) {
        Ok(code) => println!("{:0digits$}", code, digits = args.digits as usize),
        Err(err) => print_error_and_exit(err.to_string().as_ref()),
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
        (u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) as u64)
            % 10u64.pow(digits),
    )
}

fn read_line_from_stdin() -> Result<String, &'static str> {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|_| "Failed to read stdin")?;
    Ok(input.trim().to_string())
}

fn print_error_and_exit(err: &str) -> ! {
    macro_rules! red {
        ($e:expr) => {
            concat!("\x1B[31m", $e, "\x1B[0m")
        };
    }

    macro_rules! bold {
        ($e:expr) => {
            concat!("\x1B[1m", $e, "\x1B[0m")
        };
    }

    eprintln!(
        "{} {}\n\nFor more information, try '{}'.",
        bold!(red!("error:")),
        err,
        bold!("--help")
    );
    process::exit(1);
}

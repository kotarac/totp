use base32;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use std::env;
use std::io::{self, Write};
use std::process;
use std::time;

fn totp(secret: &str) -> Result<u64, &'static str> {
    let interval = 30;
    let epoch = 0;
    let digits = 6;
    let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
        .ok_or("invalid base32")?;
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

fn error(err: &str) {
    writeln!(&mut ::std::io::stderr(), "error: {}, try --help", err).unwrap();
    process::exit(1);
}

fn help() {
    println!("usage with an argument: totp <base32 secret>");
    println!("usage reading from stdin: echo <base32 secret> | totp");
}

fn handle(secret: &str) {
    match totp(secret) {
        Ok(code) => println!("{:06}", code),
        Err(err) => error(err.to_string().as_ref()),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => match stdin() {
            Ok(input) => handle(input.as_ref()),
            Err(err) => error(err.to_string().as_ref()),
        },
        2 => match args[1].as_ref() {
            "-h" => help(),
            "--help" => help(),
            _ => handle(args[1].as_ref()),
        },
        _ => {
            error("invalid usage");
        }
    }
}

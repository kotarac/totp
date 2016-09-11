extern crate base32;
extern crate oath;

use std::io::{self,Write};
use std::env;
use std::process;

fn totp(secret: &str) -> Result<u64, &'static str> {
	let secret_bytes = try!(base32::decode(base32::Alphabet::RFC4648 {padding: false}, secret).ok_or("invalid base32"));
	let code: u64 = oath::totp_raw(&secret_bytes, 6, 0, 30);
	Ok(code)
}

fn stdin() -> Result<String, &'static str> {
	let mut input = String::new();
	match io::stdin().read_line(&mut input) {
		Ok(_) => {
			let input: String = input.trim().to_string();
			Ok(input)
		},
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
		Ok(code) => println!("{}", code),
		Err(err) => error(err.to_string().as_ref()),
	}
}

fn main() {
	let args: Vec<String> = env::args().collect();

	match args.len() {
		1 => {
			match stdin() {
				Ok(input) => handle(input.as_ref()),
				Err(err) => error(err.to_string().as_ref()),
			}
		},
		2 => {
			match args[1].as_ref() {
				"-h" => help(),
				"--help" => help(),
				_ => handle(args[1].as_ref()),
			}
		},
		_ => {
			error("invalid usage");
		}
	}
}

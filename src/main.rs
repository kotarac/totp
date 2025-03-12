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

    /// The number of seconds that have passed since a particular epoch (defaults to current Unix time)
    #[arg(short, long)]
    seconds_since_epoch: Option<u64>,
}

fn main() {
    let args = Args::parse();

    let base32_secret = args
        .base32_secret
        .unwrap_or_else(|| read_line_from_stdin().unwrap_or_else(|s| print_error_and_exit(s)))
        .to_ascii_uppercase();

    match totp(
        &base32_secret,
        args.digits,
        args.epoch,
        args.interval,
        args.seconds_since_epoch,
    ) {
        Ok(code) => println!("{:0digits$}", code, digits = args.digits as usize),
        Err(err) => print_error_and_exit(err.to_string().as_ref()),
    };
}

fn totp(
    secret: &str,
    digits: u32,
    epoch: u64,
    interval: u64,
    optional_seconds_since_epoch: Option<u64>,
) -> Result<u32, &'static str> {
    let secret_bytes = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &secret.to_uppercase(),
    )
    .ok_or("Invalid base32")?;
    let mut hmac: Hmac<Sha1> =
        Mac::new_from_slice(&secret_bytes).expect("HMAC should take any length");
    let seconds_since_epoch = optional_seconds_since_epoch.unwrap_or_else(|| {
        time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            - epoch
    });
    hmac.update(&(seconds_since_epoch / interval).to_be_bytes());

    let result = hmac.finalize().into_bytes();
    let offset = (result[19] & 0b1111) as usize;
    Ok(
        (u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff)
            % 10u32.pow(digits),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_base32_secret() {
        let result = totp("JBSWY3DPEHPK3PXP", 6, 0, 30, Some(1234567890));
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_base32_secret() {
        let result = totp("INVALID!@#$", 6, 0, 30, Some(1234567890));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid base32");
    }

    #[test]
    fn test_rfc6238_sha1_test_vectors() {
        // Test vectors from RFC 6238 (time, expected):
        // https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
        let test_vectors = vec![
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ];

        // The secret is "12345678901234567890" in ASCII:
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        for (time, expected) in test_vectors {
            // For these test vectors, we need to use 8 digits:
            let result = totp(base32_secret, 8, 0, 30, Some(time));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected);
        }
    }

    #[test]
    fn test_different_intervals() {
        let secret = "JBSWY3DPEHPK3PXP";
        let time = 1234567890;

        // First test with a 30s interval (default):
        let result_30s = totp(secret, 6, 0, 30, Some(time));

        // Then with a 60s interval:
        let result_60s = totp(secret, 6, 0, 60, Some(time));

        // Codes should be different with different intervals:
        assert_ne!(result_30s.unwrap(), result_60s.unwrap());

        // Test that same interval produces same code:
        let time2 = time + 15; // Still in same 30s window.
        let result_same_window = totp(secret, 6, 0, 30, Some(time2));
        assert_eq!(result_30s.unwrap(), result_same_window.unwrap());

        // Test that different interval produces different code:
        let time3 = time + 30; // Next 30s window.
        let result_next_window = totp(secret, 6, 0, 30, Some(time3));
        assert_ne!(result_30s.unwrap(), result_next_window.unwrap());
    }

    #[test]
    fn test_different_epochs() {
        let secret = "JBSWY3DPEHPK3PXP";
        let time = 1234567890;

        // Test with epoch 0 (default):
        let result_epoch0 = totp(secret, 6, 0, 30, Some(time));

        // Test with custom epoch:
        let custom_epoch = 1000000000;
        // Time since custom epoch (need to adjust our time calculation):
        let adjusted_time = time - custom_epoch;
        let result_custom_epoch = totp(secret, 6, custom_epoch, 30, Some(adjusted_time));

        // Should produce different codes with different epochs:
        assert_ne!(result_epoch0.unwrap(), result_custom_epoch.unwrap());
    }

    #[test]
    fn test_case_insensitivity() {
        let time = 1234567890;

        // Test with uppercase:
        let upper_secret = "JBSWY3DPEHPK3PXP";
        let upper_result = totp(upper_secret, 6, 0, 30, Some(time));

        // Test with lowercase:
        let lower_secret = "jbswy3dpehpk3pxp";
        let lower_result = totp(lower_secret, 6, 0, 30, Some(time));

        // Results should be the same regardless of case:
        assert_eq!(upper_result.unwrap(), lower_result.unwrap());
    }
}

# totp

A Time-Based One-Time Password (TOTP) generator CLI.

## Usage

```
A Time-Based One-Time Password (TOTP) generator

Usage: totp [OPTIONS] [BASE32_SECRET]

Arguments:
  [BASE32_SECRET]  The Base32-encoded secret key (defaults to stdin)

Options:
  -i, --interval <INTERVAL>
          The time step in seconds (the token period) [default: 30]
  -e, --epoch <EPOCH>
          The Unix time form which to start counting steps [default: 0]
  -d, --digits <DIGITS>
          The number of digits in the TOTP code [default: 6]
  -s, --seconds-since-epoch <SECONDS_SINCE_EPOCH>
          The number of seconds that have passed since a particular epoch (defaults to current Unix time)
  -h, --help
          Print help (see more with '--help')
```

## License

MIT © Stipe Kotarac (https://github.com/kotarac)

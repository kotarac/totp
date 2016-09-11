# totp

CLI tool for generating TOTP codes.

## Usage

```
# lists usage information
totp -h
totp --help
```

```
# generates a code for the specified secret
totp <base32 secret>
```

```
# reads the secret from stdin and generates a code
echo <base32 secret> | totp
```

## License

MIT © Stipe Kotarac (https://github.com/kotarac)

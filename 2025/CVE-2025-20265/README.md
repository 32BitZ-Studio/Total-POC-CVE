# PoC for CVE-2025-20265

- [Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-radius-rce-TNBKf79)

## ⚠️ WARNING

This is a functional exploit for a 1-day vulnerability.

- **It can execute code on vulnerable systems.**
- **Use only on your own internal servers you are authorized to test.**
- **Unauthorized use is illegal and unethical.**

**Use at your own risk. You are responsible for your actions.**

## Building

1. [Install Rust](https://www.rust-lang.org/tools/install)
2. Build the PoC:

```sh
cargo build --release
```

## Usage

```sh
$ ./target/release/cve_2025_20265 --help
# or
$ cargo run --release -- --help
```

To debug, use the environment variable `RUST_LOG`:

```sh
RUST_LOG=debug cargo run --release -- --help
```

## Examples

```sh
# use either the build or the path to the executable file
$ alias EXE="cargo run --release"
# or
$ cargo build --release
$ alias EXE="./target/release/cve_2025_20265"

# check the target
$ EXE https://10.10.10.1:4443/

# read targets from the file
$ echo -e "https://10.10.10.1:4443\nhttp://127.0.0.1\nhttp://10.10.10.10" > targets.txt
$ EXE --from-file targets.txt
```

# Vulns in pngcheck 3.0.0

Two buffer over-read found in pngcheck 3.0.0.

- PPLT chunk: when `last_idx` < `first_idx`, `bytes_left` increases instead of decreases
- LOOP chunk: buffer overflow due to unchecked chunk size

## POC Files

- poc images:
    - [poc-loop.mng](./poc-loop.mng)
    - [poc-pplt.mng](./poc-pplt.mng)
- generator script: [poc.py](./poc.py)

## Usage

```
# generate POCs
python poc.py all

# test POCs
pngcheck -v poc-loop.mng
pngcheck poc-pplt.mng
```

## Note on sPLT Vulnerability

Although the official security advisory mentions a vulnerability in the sPLT chunk, it is difficult to exploit in practice due to the constraints of `toread` size limits and the requirement that `remainder` must be exactly divisible by `entry_sz`.

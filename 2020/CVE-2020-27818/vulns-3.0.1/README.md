# Vulns in pngcheck 3.0.1

Affected versions: 3.0.0, 3.0.1.

LOOP chunk: buffer over-read due to unchecked chunk size

POC file is identical to [vulns-3.0.0/poc-loop.mng](../vulns-3.0.0/poc-loop.mng).

## POC Files

- poc image: [poc.mng](./poc.mng)
- generator script: [poc.py](./poc.py)

## Usage

```
# generate POC
python poc.py

# test POC
pngcheck -v poc.mng
```

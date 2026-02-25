# Vulns in pngcheck 2.4.0

Multiple vulnerabilities found in pngcheck 2.4.0, including:

- Buffer over-read in MNG chunks (DBYK, DISC, DROP, LOOP, nEED, ORDR, PAST, PPLT, SAVE, SEEK)
- Null-pointer dereference in sCAL chunk

## POC Files

- buffer out-of-bounds:
    - [poc-dbyk.mng](./poc-dbyk.mng)
    - [poc-disc.mng](./poc-disc.mng)
    - [poc-drop.mng](./poc-drop.mng)
    - [poc-loop.mng](./poc-loop.mng)
    - [poc-need.mng](./poc-need.mng)
    - [poc-ordr.mng](./poc-ordr.mng)
    - [poc-past.mng](./poc-past.mng)
    - [poc-pplt.mng](./poc-pplt.mng)
    - [poc-save.mng](./poc-save.mng)
    - [poc-seek.mng](./poc-seek.mng)
- null-pointer dereference:
    - [poc-scal.png](./poc-scal.png)
- generator script: [poc.py](./poc.py)

## Usage

```
# generate POCs
python poc.py all

# test POCs
pngcheck -f poc-dbyk.mng
pngcheck -v poc-disc.mng
pngcheck poc-drop.mng
pngcheck -v poc-loop.mng
pngcheck -v poc-need.mng
pngcheck poc-ordr.mng
pngcheck -f poc-past.mng
pngcheck poc-pplt.mng
pngcheck -v poc-save.mng
pngcheck -v poc-seek.mng
pngcheck -f poc-scal.png
```

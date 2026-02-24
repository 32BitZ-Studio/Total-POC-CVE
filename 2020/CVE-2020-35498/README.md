# cve-2020-35498-flag
Flag the cve-2020-35498 attack

## Build
Requires `gcc` and `go`.
```
make
```

### Filter
The filter was built with `bpf_asm` and placed in `filter.c`.

## Catch the vulnerability with
```
sudo ./target/catch
```

## Trigger with
Trigger the vulnerability through interface wlan0 with destination aa:bb:cc:dd:ee:ff.
```
sudo ./target/trigger -i wlan0 -a aa:bb:cc:dd:ee:ff
```

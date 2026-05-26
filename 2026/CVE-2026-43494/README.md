# pintheft-go

Go port of [pintheft](https://github.com/v12-security/pocs/tree/main/pintheft) - RDS zcopy double-free LPE. Member of the [Dirty Frag](https://github.com/V4bel/dirtyfrag) vulnerability class.

> [!IMPORTANT]
> Arch Linux is one of the most exposed distributions for this vulnerability, as it is among the few where the RDS module can typically be loaded by default.

## How it works (tl;dr)

The bug is in `rds_message_zcopy_from_user()`. The function GUP-pins user pages one at a time via `FOLL_GET`. If a later page faults (e.g. a `PROT_NONE` guard page), the error path calls `put_page()` on already-pinned pages, then `rds_message_purge()` calls `__free_page()` on them again because `op_mmp_znotifier` was NULLed but `op_nents`/sg entries were left intact. When the page still has other references, `__free_page` silently decrements the refcount. Each failing `sendmsg` steals exactly one ref from the first page.

### Bypassing `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`

Pin the target page via `io_uring REGISTER_BUFFERS`, which adds `GUP_PIN_COUNTING_BIAS` (1024) to the refcount through `FOLL_PIN`. Steal all 1024 pin refs with failing zcopy sends. The page refcount is now ~1 (just the PTE mapping). `munmap` takes the normal `__folio_put` path, which calls `mem_cgroup_uncharge` (clearing `memcg_data`) before freeing. No `bad_page` check fires.

### Dangling bvec write

`io_uring` keeps the raw `struct page*` in its bvec array with no liveness checks. After the page is reclaimed as page cache for a suid binary, `IORING_OP_READ_FIXED` writes our payload into it through that dangling pointer.

### Preventing unpin on ring close

`IORING_REGISTER_CLONE_BUFFERS` increments `imu->refs`. A forked daemon child holds the clone ring fd open - `io_buffer_unmap` sees `refs > 1` and skips `unpin_user_folio`, preventing refcount corruption on the freed page.

### PCP LIFO

Pin to CPU 0, drain stale PCP entries before freeing - our page lands at the top when the page cache allocator grabs it.

## Exploit chain

```text
REGISTER_BUFFERS(+1024) -> CLONE_BUFFERS(imu->refs=2) ->
daemon holds clone -> steal 1024 refs -> evict page cache ->
drain PCP -> munmap(free) -> pread(reclaim) ->
READ_FIXED(overwrite) -> verify -> exec -> root
```

## Usage

```bash
go build -o pintheft-go .
./pintheft-go
```

On success drops into a root shell via PTY. The on-disk binary is untouched.

### Cleanup

```bash
sudo cp /tmp/.backup_pintheft_<pid> /usr/bin/su && sudo chmod u+s /usr/bin/su
```

## Requirements

- Linux kernel with unpatched RDS + io_uring
- `CONFIG_RDS=m`, `CONFIG_RDS_TCP=m` (autoloaded via `SO_RDS_TRANSPORT=2`)
- `CONFIG_IO_URING=y` with `io_uring_disabled=0`
- Readable suid-root binary
- No capabilities needed

## References

- [v12-security/pocs - pintheft](https://github.com/v12-security/pocs/tree/main/pintheft) - original C PoC

## Credits

- **Aaron Esau / V12 team** - vulnerability discovery and original PoC

---

_btw i love Arch Linux :)_

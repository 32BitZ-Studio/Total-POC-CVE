package main

import (
	"fmt"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427

	iORING_OFF_SQ_RING = 0
	iORING_OFF_CQ_RING = 0x8000000
	iORING_OFF_SQES    = 0x10000000

	iORING_REGISTER_BUFFERS      = 0
	iORING_REGISTER_CLONE_BUFFERS = 30

	iORING_OP_READ_FIXED = 4

	iORING_ENTER_GETEVENTS = 1
)

// io_uring_params layout (kernel ABI)
type iouringParams struct {
	sqEntries    uint32
	cqEntries    uint32
	flags        uint32
	sqThreadCPU  uint32
	sqThreadIdle uint32
	features     uint32
	wqFd         uint32
	resv         [3]uint32
	sqOff        sqringOffsets
	cqOff        cqringOffsets
}

type sqringOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	flags       uint32
	dropped     uint32
	array       uint32
	resv1       uint32
	userAddr    uint64
}

type cqringOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	overflow    uint32
	cqes        uint32
	flags       uint32
	resv1       uint32
	userAddr    uint64
}

// io_uring_sqe - 64 bytes
type iouringSQE struct {
	opcode   uint8
	flags    uint8
	ioprio   uint16
	fd       int32
	off      uint64
	addr     uint64
	length   uint32
	rwFlags  uint32
	userData uint64
	bufIndex uint16
	personality uint16
	spliceFdIn int32
	addr3    uint64
	pad2     uint64
}

// io_uring_cqe
type iouringCQE struct {
	userData uint64
	res      int32
	flags    uint32
}

// io_uring_clone_buffers
type iouringCloneBuffers struct {
	srcFd  uint32
	flags  uint32
	srcOff uint32
	dstOff uint32
	nr     uint32
	pad    [3]uint32
}

type uring struct {
	fd       int
	sqRing   uintptr
	cqRing   uintptr
	sqes     uintptr
	sqRingSz uintptr
	cqRingSz uintptr
	sqesSz   uintptr
	sqHead   *uint32
	sqTail   *uint32
	sqMask   *uint32
	sqArray  *uint32
	cqHead   *uint32
	cqTail   *uint32
	cqMask   *uint32
	cqes     *iouringCQE
}

func uringSetup(entries uint32) (*uring, error) {
	var p iouringParams
	fd, _, errno := syscall.Syscall(sysIoUringSetup, uintptr(entries), uintptr(unsafe.Pointer(&p)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup: %w", errno)
	}

	r := &uring{fd: int(fd)}

	r.sqRingSz = uintptr(p.sqOff.array) + uintptr(p.sqEntries)*4
	r.cqRingSz = uintptr(p.cqOff.cqes) + uintptr(p.cqEntries)*16
	r.sqesSz = uintptr(p.sqEntries) * 64

	sqRing, _, errno := syscall.Syscall6(syscall.SYS_MMAP, 0, r.sqRingSz,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd), iORING_OFF_SQ_RING)
	if errno != 0 {
		syscall.Close(int(fd))
		return nil, fmt.Errorf("mmap sq_ring: %w", errno)
	}
	r.sqRing = sqRing

	cqRing, _, errno := syscall.Syscall6(syscall.SYS_MMAP, 0, r.cqRingSz,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd), iORING_OFF_CQ_RING)
	if errno != 0 {
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(sqRing))[:r.sqRingSz])
		syscall.Close(int(fd))
		return nil, fmt.Errorf("mmap cq_ring: %w", errno)
	}
	r.cqRing = cqRing

	sqes, _, errno := syscall.Syscall6(syscall.SYS_MMAP, 0, r.sqesSz,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd), iORING_OFF_SQES)
	if errno != 0 {
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(cqRing))[:r.cqRingSz])
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(sqRing))[:r.sqRingSz])
		syscall.Close(int(fd))
		return nil, fmt.Errorf("mmap sqes: %w", errno)
	}
	r.sqes = sqes

	r.sqHead = (*uint32)(unsafe.Pointer(sqRing + uintptr(p.sqOff.head)))
	r.sqTail = (*uint32)(unsafe.Pointer(sqRing + uintptr(p.sqOff.tail)))
	r.sqMask = (*uint32)(unsafe.Pointer(sqRing + uintptr(p.sqOff.ringMask)))
	r.sqArray = (*uint32)(unsafe.Pointer(sqRing + uintptr(p.sqOff.array)))
	r.cqHead = (*uint32)(unsafe.Pointer(cqRing + uintptr(p.cqOff.head)))
	r.cqTail = (*uint32)(unsafe.Pointer(cqRing + uintptr(p.cqOff.tail)))
	r.cqMask = (*uint32)(unsafe.Pointer(cqRing + uintptr(p.cqOff.ringMask)))
	r.cqes = (*iouringCQE)(unsafe.Pointer(cqRing + uintptr(p.cqOff.cqes)))

	logf("io_uring fd=%d sq_ring@%#x(sz=%#x) cq_ring@%#x(sz=%#x) sqes@%#x(sz=%#x)",
		fd, sqRing, r.sqRingSz, cqRing, r.cqRingSz, sqes, r.sqesSz)
	return r, nil
}

func uringRegisterBuffers(r *uring, buf uintptr, length uintptr) error {
	iov := syscall.Iovec{Base: (*byte)(unsafe.Pointer(buf)), Len: uint64(length)}
	_, _, errno := syscall.Syscall6(sysIoUringRegister,
		uintptr(r.fd), iORING_REGISTER_BUFFERS,
		uintptr(unsafe.Pointer(&iov)), 1, 0, 0)
	if errno != 0 {
		return fmt.Errorf("io_uring_register buffers: %w", errno)
	}
	return nil
}

func uringCloneBuffers(dst, src *uring) error {
	arg := iouringCloneBuffers{srcFd: uint32(src.fd)}
	_, _, errno := syscall.Syscall6(sysIoUringRegister,
		uintptr(dst.fd), iORING_REGISTER_CLONE_BUFFERS,
		uintptr(unsafe.Pointer(&arg)), 1, 0, 0)
	if errno != 0 {
		return fmt.Errorf("io_uring clone buffers: %w", errno)
	}
	return nil
}

func uringSubmitReadFixed(r *uring, fileFd int, buf uintptr, length uint32) error {
	tail := atomic.LoadUint32(r.sqTail)
	idx := tail & *r.sqMask

	sqe := (*iouringSQE)(unsafe.Pointer(r.sqes + uintptr(idx)*64))
	*sqe = iouringSQE{}
	sqe.opcode = iORING_OP_READ_FIXED
	sqe.fd = int32(fileFd)
	sqe.off = 0
	sqe.addr = uint64(buf)
	sqe.length = length
	sqe.bufIndex = 0
	sqe.userData = 0x1234

	*(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(r.sqArray)) + uintptr(idx)*4)) = idx
	atomic.StoreUint32(r.sqTail, tail+1)

	_, _, errno := syscall.Syscall6(sysIoUringEnter,
		uintptr(r.fd), 1, 1, iORING_ENTER_GETEVENTS, 0, 0)
	if errno != 0 {
		return fmt.Errorf("io_uring_enter: %w", errno)
	}
	return nil
}

func uringWaitCQE(r *uring) (int32, error) {
	head := atomic.LoadUint32(r.cqHead)
	for i := 0; i < 1000; i++ {
		tail := atomic.LoadUint32(r.cqTail)
		if head != tail {
			break
		}
		syscall.Nanosleep(&syscall.Timespec{Nsec: 1_000_000}, nil)
	}
	tail := atomic.LoadUint32(r.cqTail)
	if head == tail {
		return 0, fmt.Errorf("CQE timeout")
	}
	idx := head & *r.cqMask
	cqe := (*iouringCQE)(unsafe.Pointer(uintptr(unsafe.Pointer(r.cqes)) + uintptr(idx)*16))
	res := cqe.res
	atomic.StoreUint32(r.cqHead, head+1)
	return res, nil
}

func uringDestroy(r *uring) {
	if r == nil {
		return
	}
	if r.sqes != 0 {
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(r.sqes))[:r.sqesSz])
	}
	if r.cqRing != 0 {
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(r.cqRing))[:r.cqRingSz])
	}
	if r.sqRing != 0 {
		syscall.Munmap((*[1 << 30]byte)(unsafe.Pointer(r.sqRing))[:r.sqRingSz])
	}
	if r.fd >= 0 {
		syscall.Close(r.fd)
		r.fd = -1
	}
}

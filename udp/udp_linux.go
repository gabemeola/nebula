//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"golang.org/x/sys/unix"
)

//TODO: make it support reload as best you can!

type StdConn struct {
	sysFd     int
	isV4      bool
	l         *logrus.Logger
	batch     int
	sockaddr4 *unix.RawSockaddrInet4
	sockaddr6 *unix.RawSockaddrInet6
	useGSO    bool
	useGRO    bool
	// Pre-allocated structures for sendmsg
	iov4 unix.Iovec
	msg4 unix.Msghdr
	iov6 unix.Iovec
	msg6 unix.Msghdr
}

func maybeIPV4(ip net.IP) (net.IP, bool) {
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4, true
	}
	return ip, false
}

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	af := unix.AF_INET6
	if ip.Is4() {
		af = unix.AF_INET
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(af, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	// Set larger buffer sizes for high throughput
	// TODO: Experimental stuff
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 16*1024*1024); err != nil {
		l.WithError(err).Warn("Failed to set SO_SNDBUF")
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 16*1024*1024); err != nil {
		l.WithError(err).Warn("Failed to set SO_RCVBUF")
	}
	// Verify the buffer sizes
	if sbuf, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil {
		l.WithField("send_buffer_size", sbuf).Info("Socket send buffer size")
	} else {
		l.WithError(err).Warn("Failed to get SO_SNDBUF")
	}
	if rbuf, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
		l.WithField("recv_buffer_size", rbuf).Info("Socket receive buffer size")
	} else {
		l.WithError(err).Warn("Failed to get SO_RCVBUF")
	}

	// Try setting SO_INCOMING_CPU to distribute load
	// TODO: Experimental stuff
	for i := 0; i < runtime.NumCPU(); i++ {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, i); err == nil {
			if cpu, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU); err == nil {
				l.WithField("cpu", cpu).Debug("Set SO_INCOMING_CPU")
				break
			}
		}
	}

	useGSO := false
	useGRO := false
	// TODO: Set MTU from config
	if err = unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_SEGMENT, 1300); err == nil {
		useGSO = true
		l.Info("UDP GSO enabled successfully")
	} else {
		l.WithError(err).Debug("UDP GSO not available, falling back to standard UDP")
	}

	// Try to enable UDP_GRO option
	if err = unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_GRO, 1); err == nil {
		useGRO = true
		l.Info("UDP GRO enabled successfully")
	} else {
		l.WithError(err).Debug("UDP GRO not available, falling back to standard UDP receive")
	}

	//TODO: support multiple listening IPs (for limiting ipv6)
	var sa unix.Sockaddr
	if ip.Is4() {
		sa4 := &unix.SockaddrInet4{Port: port}
		sa4.Addr = ip.As4()
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: port}
		sa6.Addr = ip.As16()
		sa = sa6
	}
	if err = unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	var sockaddr4 = new(unix.RawSockaddrInet4)
	sockaddr4.Family = unix.AF_INET
	var sockaddr6 = new(unix.RawSockaddrInet6)
	sockaddr6.Family = unix.AF_INET6

	// Initialize the pre-allocated message structures
	var (
		iov4 unix.Iovec
		msg4 unix.Msghdr
		iov6 unix.Iovec
		msg6 unix.Msghdr
	)

	// For IPv4
	msg4.Name = (*byte)(unsafe.Pointer(sockaddr4))
	msg4.Namelen = unix.SizeofSockaddrInet4
	msg4.Iov = &iov4
	msg4.Iovlen = 1

	// For IPv6
	msg6.Name = (*byte)(unsafe.Pointer(sockaddr6))
	msg6.Namelen = unix.SizeofSockaddrInet6
	msg6.Iov = &iov6
	msg6.Iovlen = 1

	return &StdConn{
		sysFd:     fd,
		isV4:      ip.Is4(),
		l:         l,
		batch:     batch,
		sockaddr4: sockaddr4,
		sockaddr6: sockaddr6,
		useGSO:    useGSO,
		useGRO:    useGRO,
		iov4:      iov4,
		msg4:      msg4,
		iov6:      iov6,
		msg6:      msg6,
	}, err
}

func (u *StdConn) Rebind() error {
	return nil
}

func (u *StdConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *StdConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *StdConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *StdConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	sa, err := unix.Getsockname(u.sysFd)
	if err != nil {
		return netip.AddrPort{}, err
	}

	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil

	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported sock type: %T", sa)
	}
}

const GRO_MTU = 65536

func (u *StdConn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	bufferSize := MTU
	// If GRO is enabled, we need a larger buffer for potential coalesced packets
	if u.useGRO {
		bufferSize = GRO_MTU
	}

	plaintext := make([]byte, bufferSize)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	var ip netip.Addr
	nb := make([]byte, 12, 12)

	//TODO: should we track this?
	//metric := metrics.GetOrRegisterHistogram("test.batch_read", nil, metrics.NewExpDecaySample(1028, 0.015))
	msgs, buffers, names := u.PrepareRawMessages(u.batch)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
		}

		//metric.Update(int64(n))
		for i := range n {
			name := names[i]
			// perf: early bounds check
			_ = name[24:]

			// Ensure we never access beyond the actual received data length
			if msgs[i].Len > uint32(len(buffers[i])) {
				u.l.WithFields(logrus.Fields{
					"received_len": msgs[i].Len,
					"buffer_size":  len(buffers[i]),
				}).Error("Received message larger than buffer, truncating")
				msgs[i].Len = uint32(len(buffers[i]))
			}

			if u.isV4 {
				ip, _ = netip.AddrFromSlice(name[4:8])
				//TODO: IPV6-WORK what is not ok?
			} else {
				ip, _ = netip.AddrFromSlice(name[8:24])
				//TODO: IPV6-WORK what is not ok?
			}
			r(
				netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(name[2:4])),
				plaintext[:0],
				buffers[i][:msgs[i].Len],
				h,
				fwPacket,
				lhf,
				nb,
				q,
				cache.Get(u.l),
			)
		}
	}
}

func (u *StdConn) ReadSingle(msgs []rawMessage) (int, error) {
	n, _, err := unix.Syscall6(
		unix.SYS_RECVMSG,
		uintptr(u.sysFd),
		uintptr(unsafe.Pointer(&(msgs[0].Hdr))),
		0,
		0,
		0,
		0,
	)

	if err != 0 {
		return 0, &net.OpError{Op: "recvmsg", Err: err}
	}

	msgs[0].Len = uint32(n)
	return 1, nil
}

func (u *StdConn) ReadMulti(msgs []rawMessage) (int, error) {
	var flags uintptr = unix.MSG_WAITFORONE
	// If GRO is enabled, we should be prepared for larger packets
	if u.useGRO {
		// MSG_TRUNC will let us know if the datagram was truncated
		flags |= unix.MSG_TRUNC
	}

	n, _, err := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(u.sysFd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		flags,
		0,
		0,
	)

	if err != 0 {
		return 0, &net.OpError{Op: "recvmmsg", Err: err}
	}

	// When using GRO, check if any packets were truncated
	// if u.useGRO {
	// 	for i := 0; i < int(n); i++ {
	// 		// If message flags indicate truncation, log it
	// 		if msgs[i].Flags&unix.MSG_TRUNC != 0 {
	// 			u.l.WithFields(logrus.Fields{
	// 				"received_size": msgs[i].Len,
	// 				"buffer_size":   len(msgs[i].Buf),
	// 			}).Warn("Received UDP packet was truncated, consider increasing buffer size")
	// 		}
	// 	}
	// }

	return int(n), nil
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	if u.isV4 {
		return u.writeTo4(b, ip)
	}
	return u.writeTo6(b, ip)
}

func (u *StdConn) writeTo6(b []byte, ip netip.AddrPort) error {
	u.sockaddr6.Addr = ip.Addr().As16()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&u.sockaddr6.Port))[:], ip.Port())

	// Using GSO for large packets
	if u.useGSO {
		var iov unix.Iovec
		iov.Base = &b[0]
		iov.Len = uint64(len(b))

		// var msg unix.Msghdr
		// msg.Name = (*byte)(unsafe.Pointer(u.sockaddr6))
		// msg.Namelen = unix.SizeofSockaddrInet6
		// msg.Iov = &iov
		// msg.Iovlen = 1
		u.msg6.Iov = &iov

		_, _, err := unix.Syscall(unix.SYS_SENDMSG, uintptr(u.sysFd), uintptr(unsafe.Pointer(&u.msg6)), 0)
		if err != 0 {
			return &net.OpError{Op: "sendmsg", Err: err}
		}
	} else {
		// Standard path for normal sized packets
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(u.sockaddr6)),
			uintptr(unix.SizeofSockaddrInet6),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}
	}

	//TODO: handle incomplete writes

	return nil
}

func (u *StdConn) writeTo4(b []byte, ip netip.AddrPort) error {
	if !ip.Addr().Is4() {
		return fmt.Errorf("Listener is IPv4, but writing to IPv6 remote")
	}

	u.sockaddr4.Addr = ip.Addr().As4()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&u.sockaddr4.Port))[:], ip.Port())

	// GSO path - using sendmsg instead of sendto
	if u.useGSO {
		var iov unix.Iovec
		iov.Base = &b[0]
		iov.Len = uint64(len(b))

		// var msg unix.Msghdr
		// msg.Name = (*byte)(unsafe.Pointer(u.sockaddr4))
		// msg.Namelen = unix.SizeofSockaddrInet4
		// msg.Iov = &iov
		// msg.Iovlen = 1

		u.msg4.Iov = &iov

		// Send with GSO
		_, _, err := unix.Syscall(unix.SYS_SENDMSG, uintptr(u.sysFd), uintptr(unsafe.Pointer(&u.msg4)), uintptr(0))
		if err != 0 {
			return &net.OpError{Op: "sendmsg", Err: err}
		}
	} else {
		// Original non-GSO path (unchanged)
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(u.sockaddr4)),
			uintptr(unix.SizeofSockaddrInet4),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}
	}

	//TODO: handle incomplete writes

	return nil
}

func (u *StdConn) ReloadConfig(c *config.C) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := u.SetRecvBuffer(b)
		if err == nil {
			s, err := u.GetRecvBuffer()
			if err == nil {
				u.l.WithField("size", s).Info("listen.read_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.read_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				u.l.WithField("size", s).Info("listen.write_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.write_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.write_buffer")
		}
	}
}

func (u *StdConn) getMemInfo(meminfo *[unix.SK_MEMINFO_VARS]uint32) error {
	var vallen uint32 = 4 * unix.SK_MEMINFO_VARS
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(u.sysFd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func (u *StdConn) Close() error {
	//TODO: this will not interrupt the read loop
	return syscall.Close(u.sysFd)
}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// Check if our kernel supports SO_MEMINFO before registering the gauges
	var udpGauges [][unix.SK_MEMINFO_VARS]metrics.Gauge
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	if err := udpConns[0].(*StdConn).getMemInfo(&meminfo); err == nil {
		udpGauges = make([][unix.SK_MEMINFO_VARS]metrics.Gauge, len(udpConns))
		for i := range udpConns {
			udpGauges[i] = [unix.SK_MEMINFO_VARS]metrics.Gauge{
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rcvbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.sndbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.fwd_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_queued", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.optmem", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.backlog", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.drops", i), nil),
			}
		}
	}

	return func() {
		for i, gauges := range udpGauges {
			if err := udpConns[i].(*StdConn).getMemInfo(&meminfo); err == nil {
				for j := 0; j < unix.SK_MEMINFO_VARS; j++ {
					gauges[j].Update(int64(meminfo[j]))
				}
			}
		}
	}
}

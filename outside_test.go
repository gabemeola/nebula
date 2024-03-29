package nebula

import (
	"net"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

type recvErrorConn struct {
	udp.NoopConn
	packets [][]byte
	addr    netip.AddrPort
}

func (c *recvErrorConn) WriteTo(packet []byte, addr netip.AddrPort) error {
	c.packets = append(c.packets, append([]byte(nil), packet...))
	c.addr = addr
	return nil
}

func TestHandleEncrypted_ReceiveWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seen    uint64
		counter uint64
		allowed bool
	}{
		{name: "fresh", seen: 42, counter: 43, allowed: true},
		{name: "unseen within window", seen: 42, counter: 41, allowed: true},
		{name: "duplicate", seen: 42, counter: 42},
		{name: "outside window", seen: 4 * ReplayWindow, counter: ReplayWindow + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := test.NewLogger()
			wire := &recvErrorConn{}
			f := &Interface{l: l, outside: wire, messageMetrics: newMessageMetricsOnlyRecvError()}
			ci := &ConnectionState{window: NewBits(ReplayWindow)}
			require.True(t, ci.window.Update(l, tc.seen))
			h := &header.H{Type: header.Message, RemoteIndex: 27, MessageCounter: tc.counter}

			assert.Equal(t, tc.allowed, f.handleEncrypted(ci, netip.MustParseAddrPort("192.0.2.25:4242"), h))
			assert.Empty(t, wire.packets, "a receive-window rejection must not ask a healthy peer to destroy its tunnel")
		})
	}
}

func TestHandleEncrypted_UnknownConnection(t *testing.T) {
	public := netip.MustParseAddrPort("192.0.2.25:4242")
	private := netip.MustParseAddrPort("192.168.1.25:4242")
	for _, tc := range []struct {
		name     string
		addr     netip.AddrPort
		policy   sendRecvErrorConfig
		pending  bool
		response bool
	}{
		{name: "direct", addr: public, policy: sendRecvErrorAlways, response: true},
		{name: "own pending handshake", addr: public, policy: sendRecvErrorAlways, pending: true},
		{name: "relayed", policy: sendRecvErrorAlways},
		{name: "disabled", addr: public, policy: sendRecvErrorNever},
		{name: "private policy excludes public", addr: public, policy: sendRecvErrorPrivate},
		{name: "private policy includes private", addr: private, policy: sendRecvErrorPrivate, response: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &recvErrorConn{}
			l := test.NewLogger()
			hm := newHostMap(l, netip.MustParsePrefix("10.0.0.1/24"))
			f := &Interface{
				l:                   l,
				outside:             wire,
				messageMetrics:      newMessageMetricsOnlyRecvError(),
				sendRecvErrorConfig: tc.policy,
				handshakeManager:    NewHandshakeManager(l, hm, newTestLighthouse(), &udp.NoopConn{}, defaultHandshakeConfig),
			}
			h := &header.H{Type: header.Message, RemoteIndex: 27, MessageCounter: 42}
			if tc.pending {
				// The responder sent on its new tunnel before our stage 2 arrived.
				hh := &HandshakeHostInfo{hostinfo: &HostInfo{vpnIp: netip.MustParseAddr("10.0.0.2"), localIndexId: h.RemoteIndex}}
				f.handshakeManager.indexes[h.RemoteIndex] = hh
			}
			require.False(t, f.handleEncrypted(nil, tc.addr, h))
			if !tc.response {
				assert.Empty(t, wire.packets)
				return
			}

			require.Len(t, wire.packets, 1, "unknown direct connections must still support fast recovery")
			var response header.H
			require.NoError(t, response.Parse(wire.packets[0]))
			assert.Equal(t, header.RecvError, response.Type)
			assert.Equal(t, h.RemoteIndex, response.RemoteIndex)
			assert.Zero(t, response.MessageCounter)
			assert.Equal(t, tc.addr, wire.addr)
		})
	}
}

func Test_newPacket(t *testing.T) {
	p := &firewall.Packet{}

	// length fail
	err := newPacket([]byte{0, 1}, true, p)
	assert.EqualError(t, err, "packet is less than 20 bytes")

	// length fail with ip options
	h := ipv4.Header{
		Version: 1,
		Len:     100,
		Src:     net.IPv4(10, 0, 0, 1),
		Dst:     net.IPv4(10, 0, 0, 2),
		Options: []byte{0, 1, 0, 2},
	}

	b, _ := h.Marshal()
	err = newPacket(b, true, p)

	assert.EqualError(t, err, "packet is less than 28 bytes, ip header len: 24")

	// not an ipv4 packet
	err = newPacket([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet is not ipv4, type: 0")

	// invalid ihl
	err = newPacket([]byte{4<<4 | (8 >> 2 & 0x0f), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true, p)
	assert.EqualError(t, err, "packet had an invalid header length: 8")

	// account for variable ip header length - incoming
	h = ipv4.Header{
		Version:  1,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
		Protocol: firewall.ProtoTCP,
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 3, 0, 4}...)
	err = newPacket(b, true, p)

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(firewall.ProtoTCP))
	assert.Equal(t, p.LocalIP, netip.MustParseAddr("10.0.0.2"))
	assert.Equal(t, p.RemoteIP, netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, p.RemotePort, uint16(3))
	assert.Equal(t, p.LocalPort, uint16(4))

	// account for variable ip header length - outgoing
	h = ipv4.Header{
		Version:  1,
		Protocol: 2,
		Len:      100,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Options:  []byte{0, 1, 0, 2},
	}

	b, _ = h.Marshal()
	b = append(b, []byte{0, 5, 0, 6}...)
	err = newPacket(b, false, p)

	assert.Nil(t, err)
	assert.Equal(t, p.Protocol, uint8(2))
	assert.Equal(t, p.LocalIP, netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, p.RemoteIP, netip.MustParseAddr("10.0.0.2"))
	assert.Equal(t, p.RemotePort, uint16(6))
	assert.Equal(t, p.LocalPort, uint16(5))
}

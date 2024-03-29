//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A responder makes its new tunnel primary when it answers stage 1, so its
// traffic can reach the initiator before stage 2 does. The initiator must not
// answer that traffic with recv_error: the index is its own pending
// handshake. Doing so made the responder close the new tunnel, and then the
// initiator's tunnel too, which repeated about once a second under load.
func TestPendingIndexNoRecvError(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	settings := func() m {
		return m{"timers": m{
			"connection_alive_interval": 60,
			"pending_deletion_interval": 60,
		}}
	}
	a, aNet, aAddr, _ := newSimpleServer(ca, caKey, "pending-a", "10.128.0.25/24", settings())
	b, bNet, bAddr, _ := newSimpleServer(ca, caKey, "pending-b", "10.128.0.27/24", settings())
	a.InjectLightHouseAddr(bNet.Addr(), bAddr)
	a.Start()
	b.Start()
	defer a.Stop()
	defer b.Stop()

	readUDP := func(c *nebula.Control) *udp.Packet {
		t.Helper()
		select {
		case p := <-c.GetUDPTxChan():
			require.NotNil(t, p)
			return p
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a udp packet")
			return nil
		}
	}
	readTun := func(c *nebula.Control) []byte {
		t.Helper()
		select {
		case p := <-c.GetTunTxChan():
			require.NotNil(t, p)
			return p
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a decrypted packet")
			return nil
		}
	}
	typeOf := func(p *udp.Packet) header.MessageType {
		t.Helper()
		var h header.H
		require.NoError(t, h.Parse(p.Data))
		return h.Type
	}

	// First tunnel, a initiates.
	a.InjectTunUDPPacket(bNet.Addr(), 80, 90, []byte("first"))
	b.InjectUDPPacket(readUDP(a))
	a.InjectUDPPacket(readUDP(b))
	b.InjectUDPPacket(readUDP(a))
	assertUdpPacket(t, []byte("first"), readTun(b), aNet.Addr(), bNet.Addr(), 90, 80)
	assertHostInfoPair(t, aAddr, bAddr, aNet.Addr(), bNet.Addr(), a, b)

	// a loses the tunnel on its own (a recv_error, a restart) and handshakes
	// again while b still has the old one.
	require.True(t, a.CloseTunnel(bNet.Addr(), true))
	a.InjectLightHouseAddr(bNet.Addr(), bAddr)
	a.InjectTunUDPPacket(bNet.Addr(), 80, 90, []byte("second"))
	stage1 := readUDP(a)
	require.Equal(t, header.Handshake, typeOf(stage1))
	b.InjectUDPPacket(stage1)
	stage2 := readUDP(b)
	require.Equal(t, header.Handshake, typeOf(stage2))

	// b takes the new handshake and sends on it before a has stage 2, more
	// than the 4 recv_errors it takes to close a tunnel.
	var early []*udp.Packet
	for i := 0; i < 5; i++ {
		b.InjectTunUDPPacket(aNet.Addr(), 90, 80, []byte("early"))
		p := readUDP(b)
		require.Equal(t, header.Message, typeOf(p))
		early = append(early, p)
	}
	for _, p := range early {
		a.InjectUDPPacket(p)
	}
	a.InjectUDPPacket(stage2)

	// a's UDP output is FIFO: a recv_error for an early packet would come
	// before the cached "second" packet. Skip stage 1 retransmits.
	recvErrors := 0
	var cached *udp.Packet
	for cached == nil {
		p := readUDP(a)
		switch typeOf(p) {
		case header.Handshake:
		case header.RecvError:
			recvErrors++
			b.InjectUDPPacket(p)
		case header.Message:
			cached = p
		default:
			t.Fatalf("unexpected packet type %v from a", typeOf(p))
		}
	}
	assert.Zero(t, recvErrors, "a answered traffic for its pending index with recv_error")
	b.InjectUDPPacket(cached)
	assertUdpPacket(t, []byte("second"), readTun(b), aNet.Addr(), bNet.Addr(), 90, 80)
	assertHostInfoPair(t, aAddr, bAddr, aNet.Addr(), bNet.Addr(), a, b)

	b.InjectTunUDPPacket(aNet.Addr(), 90, 80, []byte("reply"))
	a.InjectUDPPacket(readUDP(b))
	assertUdpPacket(t, []byte("reply"), readTun(a), bNet.Addr(), aNet.Addr(), 80, 90)
}

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

func TestAuthenticatedReplayKeepsTunnel(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	settings := func() m {
		return m{"timers": m{
			"connection_alive_interval": 60,
			"pending_deletion_interval": 60,
		}}
	}
	a, aNet, aAddr, _ := newSimpleServer(ca, caKey, "replay-a", "10.128.0.25/24", settings())
	b, bNet, bAddr, _ := newSimpleServer(ca, caKey, "replay-b", "10.128.0.27/24", settings())
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
			t.Fatal("timed out waiting for an encrypted packet")
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

	// Complete a real Noise handshake and deliver its first cached data packet.
	// All traffic stays in the in-memory test UDP/TUN devices.
	a.InjectTunUDPPacket(bNet.Addr(), 80, 90, []byte("before replay"))
	b.InjectUDPPacket(readUDP(a))
	a.InjectUDPPacket(readUDP(b))
	data := readUDP(a)
	var h header.H
	require.NoError(t, h.Parse(data.Data))
	require.Equal(t, header.Message, h.Type)
	require.Equal(t, header.MessageNone, h.Subtype)
	b.InjectUDPPacket(data.Copy())
	assertUdpPacket(t, []byte("before replay"), readTun(b), aNet.Addr(), bNet.Addr(), 90, 80)
	assertHostInfoPair(t, aAddr, bAddr, aNet.Addr(), bNet.Addr(), a, b)
	originalA := a.GetHostInfoByVpnIp(bNet.Addr(), false)
	originalB := b.GetHostInfoByVpnIp(aNet.Addr(), false)
	require.NotNil(t, originalA)
	require.NotNil(t, originalB)

	b.InjectUDPPacket(data.Copy())
	// A subsequent authenticated packet is a FIFO receive-loop barrier. Once
	// delivered, the replay has been processed; no timing-based quiet wait is
	// needed to check for a recv_error or a duplicate TUN delivery.
	a.InjectTunUDPPacket(bNet.Addr(), 80, 90, []byte("after replay"))
	b.InjectUDPPacket(readUDP(a))
	assertUdpPacket(t, []byte("after replay"), readTun(b), aNet.Addr(), bNet.Addr(), 90, 80)
	assert.Empty(t, b.GetFromTun(false), "replayed data must not be delivered twice")
	require.Nil(t, b.GetFromUDP(false), "rejecting a replay must not generate recv_error")

	b.InjectTunUDPPacket(aNet.Addr(), 90, 80, []byte("reply after replay"))
	a.InjectUDPPacket(readUDP(b))
	assertUdpPacket(t, []byte("reply after replay"), readTun(a), bNet.Addr(), aNet.Addr(), 80, 90)
	currentA := a.GetHostInfoByVpnIp(bNet.Addr(), false)
	currentB := b.GetHostInfoByVpnIp(aNet.Addr(), false)
	require.NotNil(t, currentA)
	require.NotNil(t, currentB)
	assert.Equal(t, originalA.LocalIndex, currentA.LocalIndex)
	assert.Equal(t, originalA.RemoteIndex, currentA.RemoteIndex)
	assert.Equal(t, originalB.LocalIndex, currentB.LocalIndex)
	assert.Equal(t, originalB.RemoteIndex, currentB.RemoteIndex)
}

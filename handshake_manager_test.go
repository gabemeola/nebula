package nebula

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeManager_TrafficWatchOnPublication(t *testing.T) {
	for _, responder := range []bool{true, false} {
		name := "initiator"
		if responder {
			name = "responder"
		}
		t.Run(name, func(t *testing.T) {
			l := test.NewLogger()
			hm := newHostMap(l, netip.MustParsePrefix("10.0.0.1/24"))
			lh := newTestLighthouse()
			handshakes := NewHandshakeManager(l, hm, lh, &udp.NoopConn{}, defaultHandshakeConfig)
			f := &Interface{l: l, hostMap: hm, lightHouse: lh, handshakeManager: handshakes}
			// Drive the real timer wheel explicitly, without a background ticker.
			cm := &connectionManager{
				l:                       l,
				hostMap:                 hm,
				intf:                    f,
				in:                      make(map[uint32]struct{}),
				inLock:                  &sync.RWMutex{},
				out:                     make(map[uint32]struct{}),
				outLock:                 &sync.RWMutex{},
				relayUsedLock:           &sync.RWMutex{},
				pendingDeletion:         make(map[uint32]struct{}),
				punchy:                  NewPunchyFromConfig(l, config.NewC(l)),
				trafficTimer:            NewLockingTimerWheel[uint32](500*time.Millisecond, 10*time.Second),
				checkInterval:           5 * time.Second,
				pendingDeletionInterval: 10 * time.Second,
			}
			f.connectionManager = cm
			hi := &HostInfo{
				vpnIp:           netip.MustParseAddr("10.0.0.2"),
				localIndexId:    1234,
				remoteIndexId:   5678,
				ConnectionState: &ConnectionState{},
				HandshakePacket: map[uint8][]byte{0: []byte("handshake")},
			}
			now := time.Now()
			cm.trafficTimer.Advance(now)
			if responder {
				_, err := handshakes.CheckAndComplete(hi, 0, f)
				require.NoError(t, err)
			} else {
				hh := &HandshakeHostInfo{hostinfo: hi}
				handshakes.vpnIps[hi.vpnIp] = hh
				handshakes.indexes[hi.localIndexId] = hh
				handshakes.Complete(hi, f)
			}
			require.Same(t, hi, hm.QueryVpnIp(hi.vpnIp))
			// Egress can run as soon as the hostmap lock is released. Previously
			// this marker made the later AddTrafficWatch silently skip the timer.
			cm.Out(hi.localIndexId)
			if responder {
				duplicate := &HostInfo{vpnIp: hi.vpnIp, localIndexId: 9999, HandshakePacket: hi.HandshakePacket}
				_, err := handshakes.CheckAndComplete(duplicate, 0, f)
				require.ErrorIs(t, err, ErrAlreadySeen)
			}

			now = now.Add(6 * time.Second)
			cm.trafficTimer.Advance(now)
			idx, ok := cm.trafficTimer.Purge()
			require.True(t, ok, "published tunnel must have a health watch despite immediate outgoing traffic")
			require.Equal(t, hi.localIndexId, idx)
			_, extra := cm.trafficTimer.Purge()
			require.False(t, extra, "publication and duplicate handshakes must not schedule extra watches")
			decision, _, _ := cm.makeTrafficDecision(idx, now)
			require.Equal(t, sendTestPacket, decision)

			// An unanswered active test must eventually evict the dead primary,
			// so future outgoing traffic can start a new handshake.
			now = now.Add(11 * time.Second)
			cm.trafficTimer.Advance(now)
			idx, ok = cm.trafficTimer.Purge()
			require.True(t, ok)
			require.Equal(t, hi.localIndexId, idx)
			cm.doTrafficCheck(idx, nil, nil, nil, now)
			assert.Nil(t, hm.QueryVpnIp(hi.vpnIp))
			assert.Nil(t, hm.QueryIndex(hi.localIndexId))
		})
	}
}

func Test_NewHandshakeManagerVpnIp(t *testing.T) {
	l := test.NewLogger()
	vpncidr := netip.MustParsePrefix("172.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	ip := netip.MustParseAddr("172.1.1.2")

	preferredRanges := []netip.Prefix{localrange}
	mainHM := newHostMap(l, vpncidr)
	mainHM.preferredRanges.Store(&preferredRanges)

	lh := newTestLighthouse()

	cs := &CertState{
		RawCertificate:      []byte{},
		PrivateKey:          []byte{},
		Certificate:         &cert.NebulaCertificate{},
		RawCertificateNoKey: []byte{},
	}

	blah := NewHandshakeManager(l, mainHM, lh, &udp.NoopConn{}, defaultHandshakeConfig)
	blah.f = &Interface{handshakeManager: blah, pki: &PKI{}, l: l}
	blah.f.pki.cs.Store(cs)

	now := time.Now()
	blah.NextOutboundHandshakeTimerTick(now)

	i := blah.StartHandshake(ip, nil)
	i2 := blah.StartHandshake(ip, nil)
	assert.Same(t, i, i2)

	i.remotes = NewRemoteList(nil)

	// Adding something to pending should not affect the main hostmap
	assert.Len(t, mainHM.Hosts, 0)

	// Confirm they are in the pending index list
	assert.Contains(t, blah.vpnIps, ip)

	// Jump ahead `HandshakeRetries` ticks, offset by one to get the sleep logic right
	for i := 1; i <= DefaultHandshakeRetries+1; i++ {
		now = now.Add(time.Duration(i) * DefaultHandshakeTryInterval)
		blah.NextOutboundHandshakeTimerTick(now)
	}

	// Confirm they are still in the pending index list
	assert.Contains(t, blah.vpnIps, ip)

	// Tick 1 more time, a minute will certainly flush it out
	blah.NextOutboundHandshakeTimerTick(now.Add(time.Minute))

	// Confirm they have been removed
	assert.NotContains(t, blah.vpnIps, ip)
}

func testCountTimerWheelEntries(tw *LockingTimerWheel[netip.Addr]) (c int) {
	for _, i := range tw.t.wheel {
		n := i.Head
		for n != nil {
			c++
			n = n.Next
		}
	}
	return c
}

type mockEncWriter struct {
}

func (mw *mockEncWriter) SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp netip.Addr, p, nb, out []byte) {
	return
}

func (mw *mockEncWriter) SendVia(via *HostInfo, relay *Relay, ad, nb, out []byte, nocopy bool) {
	return
}

func (mw *mockEncWriter) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p, nb, out []byte) {
	return
}

func (mw *mockEncWriter) Handshake(vpnIP netip.Addr) {}

// Upstream #1811: deleting an established hostinfo (handleRecvError does)
// must not drop a newer pending handshake to the same vpn ip.
func TestHandshakeManager_DeleteHostInfoKeepsOtherPending(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l, netip.MustParsePrefix("10.0.0.1/24"))
	handshakes := NewHandshakeManager(l, hm, newTestLighthouse(), &udp.NoopConn{}, defaultHandshakeConfig)
	vpnIp := netip.MustParseAddr("10.0.0.2")
	pending := &HandshakeHostInfo{hostinfo: &HostInfo{vpnIp: vpnIp, localIndexId: 1}}
	handshakes.vpnIps[vpnIp] = pending
	handshakes.indexes[1] = pending

	handshakes.DeleteHostInfo(&HostInfo{vpnIp: vpnIp, localIndexId: 2})
	assert.Same(t, pending.hostinfo, handshakes.QueryVpnIp(vpnIp))
	assert.Same(t, pending.hostinfo, handshakes.QueryIndex(1))

	handshakes.DeleteHostInfo(pending.hostinfo)
	assert.Nil(t, handshakes.QueryVpnIp(vpnIp))
	assert.Nil(t, handshakes.QueryIndex(1))
}

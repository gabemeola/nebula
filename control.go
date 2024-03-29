package nebula

import (
	"context"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay"
)

// Every interaction here needs to take extra care to copy memory and not return or use arguments "as is" when touching
// core. This means copying IP objects, slices, de-referencing pointers and taking the actual value, etc

type controlEach func(h *HostInfo)

type controlHostLister interface {
	QueryVpnIp(vpnIp netip.Addr) *HostInfo
	ForEachIndex(each controlEach)
	ForEachVpnIp(each controlEach)
	GetPreferredRanges() []netip.Prefix
}

type Control struct {
	F               *Interface
	l               *logrus.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	sshStart        func()
	statsStart      func()
	dnsStart        func()
	lighthouseStart func()
}

type ControlHostInfo struct {
	VpnIp                  netip.Addr              `json:"vpnIp"`
	LocalIndex             uint32                  `json:"localIndex"`
	RemoteIndex            uint32                  `json:"remoteIndex"`
	RemoteAddrs            []netip.AddrPort        `json:"remoteAddrs"`
	Cert                   *cert.NebulaCertificate `json:"cert"`
	MessageCounter         uint64                  `json:"messageCounter"`
	CurrentRemote          netip.AddrPort          `json:"currentRemote"`
	CurrentRelaysToMe      []netip.Addr            `json:"currentRelaysToMe"`
	CurrentRelaysThroughMe []netip.Addr            `json:"currentRelaysThroughMe"`
}

// Start actually runs nebula, this is a nonblocking call. To block use Control.ShutdownBlock()
func (c *Control) Start() {
	// Activate the interface
	c.F.activate()

	// Call all the delayed funcs that waited patiently for the interface to be created.
	if c.sshStart != nil {
		go c.sshStart()
	}
	if c.statsStart != nil {
		go c.statsStart()
	}
	if c.dnsStart != nil {
		go c.dnsStart()
	}
	if c.lighthouseStart != nil {
		c.lighthouseStart()
	}

	// Start reading packets.
	c.F.run()
}

func (c *Control) Context() context.Context {
	return c.ctx
}

// Stop signals nebula to shutdown and close all tunnels, returns after the shutdown is complete
func (c *Control) Stop() {
	// Stop the handshakeManager (and other services), to prevent new tunnels from
	// being created while we're shutting them all down.
	c.cancel()

	c.CloseAllTunnels(false)
	if err := c.F.Close(); err != nil {
		c.l.WithError(err).Error("Close interface failed")
	}
	c.l.Info("Goodbye")
}

// ShutdownBlock will listen for and block on term and interrupt signals, calling Control.Stop() once signalled
func (c *Control) ShutdownBlock() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)

	rawSig := <-sigChan
	sig := rawSig.String()
	c.l.WithField("signal", sig).Info("Caught signal, shutting down")
	c.Stop()
}

// RebindUDPServer asks the UDP listener to rebind it's listener. Mainly used on mobile clients when interfaces change
func (c *Control) RebindUDPServer() {
	_ = c.F.outside.Rebind()

	// Trigger a lighthouse update, useful for mobile clients that should have an update interval of 0
	c.F.lightHouse.SendUpdate()

	// Let the main interface know that we rebound so that underlying tunnels know to trigger punches from their remotes
	c.F.rebindCount++
}

// ListHostmapHosts returns details about the actual or pending (handshaking) hostmap by vpn ip
func (c *Control) ListHostmapHosts(pendingMap bool) []ControlHostInfo {
	if pendingMap {
		return listHostMapHosts(c.F.handshakeManager)
	} else {
		return listHostMapHosts(c.F.hostMap)
	}
}

// ListHostmapIndexes returns details about the actual or pending (handshaking) hostmap by local index id
func (c *Control) ListHostmapIndexes(pendingMap bool) []ControlHostInfo {
	if pendingMap {
		return listHostMapIndexes(c.F.handshakeManager)
	} else {
		return listHostMapIndexes(c.F.hostMap)
	}
}

// GetCertByVpnIp returns the authenticated certificate of the given vpn IP, or nil if not found
func (c *Control) GetCertByVpnIp(vpnIp netip.Addr) *cert.NebulaCertificate {
	if c.F.myVpnNet.Addr() == vpnIp {
		return c.F.pki.GetCertState().Certificate
	}
	hi := c.F.hostMap.QueryVpnIp(vpnIp)
	if hi == nil {
		return nil
	}
	return hi.GetCert()
}

// CreateTunnel creates a new tunnel to the given vpn ip.
func (c *Control) CreateTunnel(vpnIp netip.Addr) {
	c.F.handshakeManager.StartHandshake(vpnIp, nil)
}

// PrintTunnel creates a new tunnel to the given vpn ip.
func (c *Control) PrintTunnel(vpnIp netip.Addr) *ControlHostInfo {
	hi := c.F.hostMap.QueryVpnIp(vpnIp)
	if hi == nil {
		return nil
	}
	chi := copyHostInfo(hi, c.F.hostMap.GetPreferredRanges())
	return &chi
}

// QueryLighthouse queries the lighthouse.
func (c *Control) QueryLighthouse(vpnIp netip.Addr) *CacheMap {
	hi := c.F.lightHouse.Query(vpnIp)
	if hi == nil {
		return nil
	}
	return hi.CopyCache()
}

// GetHostInfoByVpnIp returns a single tunnels hostInfo, or nil if not found
// Caller should take care to Unmap() any 4in6 addresses prior to calling.
func (c *Control) GetHostInfoByVpnIp(vpnIp netip.Addr, pending bool) *ControlHostInfo {
	var hl controlHostLister
	if pending {
		hl = c.F.handshakeManager
	} else {
		hl = c.F.hostMap
	}

	h := hl.QueryVpnIp(vpnIp)
	if h == nil {
		return nil
	}

	ch := copyHostInfo(h, c.F.hostMap.GetPreferredRanges())
	return &ch
}

// SetRemoteForTunnel forces a tunnel to use a specific remote
// Caller should take care to Unmap() any 4in6 addresses prior to calling.
func (c *Control) SetRemoteForTunnel(vpnIp netip.Addr, addr netip.AddrPort) *ControlHostInfo {
	hostInfo := c.F.hostMap.QueryVpnIp(vpnIp)
	if hostInfo == nil {
		return nil
	}

	hostInfo.SetRemote(addr)
	ch := copyHostInfo(hostInfo, c.F.hostMap.GetPreferredRanges())
	return &ch
}

// CloseTunnel closes a fully established tunnel. If localOnly is false it will notify the remote end as well.
// Caller should take care to Unmap() any 4in6 addresses prior to calling.
func (c *Control) CloseTunnel(vpnIp netip.Addr, localOnly bool) bool {
	hostInfo := c.F.hostMap.QueryVpnIp(vpnIp)
	if hostInfo == nil {
		return false
	}

	if !localOnly {
		c.F.send(
			header.CloseTunnel,
			0,
			hostInfo.ConnectionState,
			hostInfo,
			[]byte{},
			make([]byte, 12, 12),
			make([]byte, mtu),
		)
	}

	c.F.closeTunnel(hostInfo)
	return true
}

// CloseAllTunnels is just like CloseTunnel except it goes through and shuts them all down, optionally you can avoid shutting down lighthouse tunnels
// the int returned is a count of tunnels closed
func (c *Control) CloseAllTunnels(excludeLighthouses bool) (closed int) {
	//TODO: this is probably better as a function in ConnectionManager or HostMap directly
	lighthouses := c.F.lightHouse.GetLighthouses()

	shutdown := func(h *HostInfo) {
		if excludeLighthouses {
			if _, ok := lighthouses[h.vpnIp]; ok {
				return
			}
		}
		c.F.send(header.CloseTunnel, 0, h.ConnectionState, h, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
		c.F.closeTunnel(h)

		c.l.WithField("vpnIp", h.vpnIp).WithField("udpAddr", h.remote).
			Debug("Sending close tunnel message")
		closed++
	}

	// Learn which hosts are being used as relays, so we can shut them down last.
	relayingHosts := map[netip.Addr]*HostInfo{}
	// Grab the hostMap lock to access the Relays map
	c.F.hostMap.Lock()
	for _, relayingHost := range c.F.hostMap.Relays {
		relayingHosts[relayingHost.vpnIp] = relayingHost
	}
	c.F.hostMap.Unlock()

	hostInfos := []*HostInfo{}
	// Grab the hostMap lock to access the Hosts map
	c.F.hostMap.Lock()
	for _, relayHost := range c.F.hostMap.Indexes {
		if _, ok := relayingHosts[relayHost.vpnIp]; !ok {
			hostInfos = append(hostInfos, relayHost)
		}
	}
	c.F.hostMap.Unlock()

	for _, h := range hostInfos {
		shutdown(h)
	}
	for _, h := range relayingHosts {
		shutdown(h)
	}
	return
}

func (c *Control) Device() overlay.Device {
	return c.F.inside
}

func copyHostInfo(h *HostInfo, preferredRanges []netip.Prefix) ControlHostInfo {

	chi := ControlHostInfo{
		VpnIp:                  h.vpnIp,
		LocalIndex:             h.localIndexId,
		RemoteIndex:            h.remoteIndexId,
		RemoteAddrs:            h.remotes.CopyAddrs(preferredRanges),
		CurrentRelaysToMe:      h.relayState.CopyRelayIps(),
		CurrentRelaysThroughMe: h.relayState.CopyRelayForIps(),
		CurrentRemote:          h.remote,
	}

	if h.ConnectionState != nil {
		chi.MessageCounter = h.ConnectionState.messageCounter.Load()
	}

	if c := h.GetCert(); c != nil {
		chi.Cert = c.Copy()
	}

	return chi
}

func listHostMapHosts(hl controlHostLister) []ControlHostInfo {
	hosts := make([]ControlHostInfo, 0)
	pr := hl.GetPreferredRanges()
	hl.ForEachVpnIp(func(hostinfo *HostInfo) {
		hosts = append(hosts, copyHostInfo(hostinfo, pr))
	})
	return hosts
}

func listHostMapIndexes(hl controlHostLister) []ControlHostInfo {
	hosts := make([]ControlHostInfo, 0)
	pr := hl.GetPreferredRanges()
	hl.ForEachIndex(func(hostinfo *HostInfo) {
		hosts = append(hosts, copyHostInfo(hostinfo, pr))
	})
	return hosts
}

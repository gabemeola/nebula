package nebula

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	l "reship/util/logger/v2"
	"sync"
	"time"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"golang.org/x/net/ipv4"
)

var httpListener *NebulaHTTPListener
var httpServer *http.Server

func (f *Interface) handleTCPSyn(ipHeader *ipv4.Header, tcpHeader *TCPHeader, hostinfo *HostInfo, nb []byte, packet []byte, q int) error {
	l.Log.Info().Msg("Handling SYN packet, sending SYN-ACK")

	// If we have an HTTP listener, handle this as a new HTTP connection
	if httpListener == nil {
		httpListener = NewNebulaHTTPListener(f)
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			l.Log.Warn().Msgf("HTTP Request: %s %s", r.Method, r.URL.Path)
			l.Log.Warn().Msgf("Host: %+v", r.Host)
			l.Log.Warn().Msgf("HEADERS: %+v", r.Header)
			// w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("HELLO WORLD " + r.Method + " " + r.URL.Path))
		})

		httpServer = &http.Server{
			Handler: mux,
		}
		// Start server in background
		l.Log.Info().Msg("Starting HTTP Server")
		go httpServer.Serve(httpListener)
	}
	if httpListener != nil {
		return httpListener.HandleNewConnection(ipHeader, tcpHeader, hostinfo, nb, packet, q)
	}

	// Generate initial sequence number for our response
	ourSeqNum := generateISN()

	// Create SYN-ACK packet
	synAckPacket, err := f.createSynAckPacket(
		ipHeader.Dst,       // Our IP (destination becomes source)
		ipHeader.Src,       // Client IP (source becomes destination)
		tcpHeader.DstPort,  // Our port (destination becomes source)
		tcpHeader.SrcPort,  // Client port (source becomes destination)
		ourSeqNum,          // Our sequence number
		tcpHeader.SeqNum+1, // Acknowledge client's SYN
	)
	if err != nil {
		return fmt.Errorf("failed to create SYN-ACK packet: %w", err)
	}

	// Send the SYN-ACK response through Nebula
	f.sendPacketResponse(synAckPacket, hostinfo, nb, packet, q)
	return nil
}

func generateISN() uint32 {
	// Generate a random initial sequence number
	// In production, this should be based on RFC 6528
	var buf [4]byte
	rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

func (f *Interface) createSynAckPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum, ackNum uint32) ([]byte, error) {
	// Create IP header
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20, // Standard IP header length
		TOS:      0,
		TotalLen: 40, // IP header (20) + TCP header (20)
		ID:       int(time.Now().UnixNano() & 0xFFFF),
		Flags:    ipv4.DontFragment,
		FragOff:  0,
		TTL:      64,
		Protocol: 6, // TCP
		Src:      srcIP,
		Dst:      dstIP,
	}

	// Create IP packet buffer
	ipPacket := make([]byte, 40)

	// Write IP header
	if err := writeIPHeader(ipPacket[:20], ipHeader); err != nil {
		return nil, fmt.Errorf("failed to write IP header: %w", err)
	}

	// Create TCP header (SYN-ACK)
	tcpHeader := ipPacket[20:]

	// TCP Header fields
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort) // Source port
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort) // Destination port
	binary.BigEndian.PutUint32(tcpHeader[4:8], seqNum)  // Sequence number
	binary.BigEndian.PutUint32(tcpHeader[8:12], ackNum) // Acknowledgment number

	// Data offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
	tcpHeader[12] = 0x50 // 5 * 4 = 20 bytes header length

	// Flags: SYN + ACK
	tcpHeader[13] = TCPFlagSYN | TCPFlagACK

	// Window size
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // Maximum window

	// Checksum (will be calculated below)
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)

	// Urgent pointer
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)

	// Calculate TCP checksum
	checksum := calculateTCPChecksum(srcIP, dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	// Calculate IP checksum
	ipChecksum := calculateIPChecksum(ipPacket[:20])
	binary.BigEndian.PutUint16(ipPacket[10:12], ipChecksum)

	return ipPacket, nil
}

func writeIPHeader(buf []byte, header *ipv4.Header) error {
	if len(buf) < 20 {
		return fmt.Errorf("buffer too small for IP header")
	}

	// Version (4 bits) + IHL (4 bits)
	buf[0] = 0x45 // Version 4, Header Length 5 * 4 = 20 bytes

	// Type of Service
	buf[1] = byte(header.TOS)

	// Total Length
	binary.BigEndian.PutUint16(buf[2:4], uint16(header.TotalLen))

	// Identification
	binary.BigEndian.PutUint16(buf[4:6], uint16(header.ID))

	// Flags (3 bits) + Fragment Offset (13 bits)
	flagsAndFragOff := uint16(header.Flags)<<13 | uint16(header.FragOff)
	binary.BigEndian.PutUint16(buf[6:8], flagsAndFragOff)

	// TTL
	buf[8] = byte(header.TTL)

	// Protocol
	buf[9] = byte(header.Protocol)

	// Header Checksum (set to 0 for calculation)
	binary.BigEndian.PutUint16(buf[10:12], 0)

	// Source IP
	copy(buf[12:16], header.Src.To4())

	// Destination IP
	copy(buf[16:20], header.Dst.To4())

	return nil
}

func calculateTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	// Create pseudo header for checksum calculation
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0 // Zero
	pseudoHeader[9] = 6 // TCP protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpHeader)))

	// Calculate checksum over pseudo header + TCP header
	return internetChecksum(append(pseudoHeader, tcpHeader...))
}

func calculateIPChecksum(ipHeader []byte) uint16 {
	return internetChecksum(ipHeader)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add odd byte if present
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}

func (f *Interface) sendPacketResponse(responsePacket []byte, hostinfo *HostInfo, nb []byte, originalPacket []byte, q int) {
	l.Log.Info().Msgf("Sending packet response (%d bytes)\n%s", len(responsePacket), responsePacket)

	// Encrypt and send the response packet through Nebula
	f.sendNoMetrics(
		header.Message,
		header.MessageNone,
		hostinfo.ConnectionState,
		hostinfo,
		netip.AddrPort{}, // Remote address (Nebula will handle routing)
		responsePacket,   // Our crafted response
		nb,
		originalPacket,
		q,
	)
}

func (f *Interface) createTCPResponse(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum, ackNum uint32, payload []byte, flags uint8) ([]byte, error) {
	payloadLen := len(payload)
	totalLen := 20 + 20 + payloadLen // IP header + TCP header + payload

	// Create packet buffer
	packet := make([]byte, totalLen)

	// Create IP header
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: totalLen,
		ID:       int(time.Now().UnixNano() & 0xFFFF),
		Flags:    ipv4.DontFragment,
		TTL:      64,
		Protocol: 6, // TCP
		Src:      srcIP,
		Dst:      dstIP,
	}

	// Write IP header
	if err := writeIPHeader(packet[:20], ipHeader); err != nil {
		return nil, err
	}

	// Write TCP header
	tcpHeader := packet[20:40]
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], seqNum)
	binary.BigEndian.PutUint32(tcpHeader[8:12], ackNum)
	tcpHeader[12] = 0x50 // Header length: 20 bytes
	tcpHeader[13] = flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // Window size
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)     // Checksum (calculated below)
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)     // Urgent pointer

	// Copy payload
	if payloadLen > 0 {
		copy(packet[40:], payload)
	}

	// Calculate TCP checksum (over header + payload)
	tcpChecksum := calculateTCPChecksum(srcIP, dstIP, packet[20:])
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum)

	// Calculate IP checksum
	ipChecksum := calculateIPChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	return packet, nil
}

func (f *Interface) handleHTTPPacket(out []byte, fwPacket *firewall.Packet, hostinfo *HostInfo, nb []byte, packet []byte, q int) error {
	// Parse IP header
	ipHeader, err := ipv4.ParseHeader(out)
	if err != nil {
		return fmt.Errorf("error parsing IP header: %w", err)
	}

	// Extract TCP data (skip IP header)
	tcpData := out[ipHeader.Len:]

	// Parse TCP header
	tcpHeader, err := parseTCPHeader(tcpData)
	if err != nil {
		return fmt.Errorf("error parsing TCP header: %w", err)
	}

	f.l.Infof("TCP: %s:%d -> %s:%d, Seq: %d, Ack: %d, Flags: %02x",
		ipHeader.Src, tcpHeader.SrcPort,
		ipHeader.Dst, tcpHeader.DstPort,
		tcpHeader.SeqNum, tcpHeader.AckNum, tcpHeader.Flags)

	// Handle different TCP states
	switch {
	// TODO: SYN new connection seems to work fine
	case tcpHeader.HasFlag(TCPFlagSYN) && !tcpHeader.HasFlag(TCPFlagACK):
		l.Log.Info().Msg("TCP SYN")
		// Initial SYN - new connection
		return f.handleTCPSyn(ipHeader, tcpHeader, hostinfo, nb, packet, q)

	case tcpHeader.HasFlag(TCPFlagACK) && !tcpHeader.HasFlag(TCPFlagSYN):
		l.Log.Info().Msg("TCP ACK")
		// ACK packet - connection established or data acknowledgment
		return f.handleTCPAck(ipHeader, tcpHeader, hostinfo, nb, out, packet, q)

	case tcpHeader.HasFlag(TCPFlagFIN):
		l.Log.Info().Msg("TCP FIN")
		// Connection termination
		return f.handleTCPFin(ipHeader, tcpHeader, hostinfo, nb, packet, q)

	case tcpHeader.HasFlag(TCPFlagRST):
		l.Log.Info().Msg("TCP RST")
		// Connection reset
		return nil

	default:
		f.l.Infof("Unhandled TCP flags: %02x", tcpHeader.Flags)
		return nil
	}
}

func (f *Interface) handleTCPAck(ipHeader *ipv4.Header, tcpHeader *TCPHeader, hostinfo *HostInfo, nb []byte, out, packet []byte, q int) error {
	// Extract HTTP payload
	tcpData := out[ipHeader.Len:]
	httpPayload := tcpData[tcpHeader.PayloadOffset():]

	if len(httpPayload) > 0 {
		f.l.Infof("Received HTTP data (%d bytes)\n%s", len(httpPayload), httpPayload)
		// connKey := fmt.Sprintf("%s:%d-%s:%d", ipHeader.Src, tcpHeader.SrcPort, ipHeader.Dst, tcpHeader.DstPort)
		// conn, hasConn := httpListener.connections[connKey]
		// l.Log.Info().Msgf("connection lookup: %v", hasConn)
		// if !hasConn {
		// 	return nil
		// }
		// var d []byte
		// copy(d, httpPayload)
		// conn.AddData(d)
		if httpListener == nil {
			l.Log.Info().Msg("httpListener not initialized yet. skipping")
			return nil
		}
		httpListener.HandlePacket(ipHeader.Src, ipHeader.Dst, tcpHeader.SrcPort, tcpHeader.DstPort, httpPayload)
		return nil

		// Process HTTP request and send response
		// return f.processHTTPRequest(httpPayload, ipHeader, tcpHeader, hostinfo, nb, packet, q)
	}

	return nil
}

func (f *Interface) processHTTPRequest(httpData []byte, ipHeader *ipv4.Header, tcpHeader *TCPHeader, hostinfo *HostInfo, nb []byte, packet []byte, q int) error {
	// Parse HTTP request (simplified)
	// httpStr := string(httpData)
	// l.Log.Info().Msgf("[processHTTPRequest] %s", httpStr)
	// if !strings.HasPrefix(httpStr, "GET ") && !strings.HasPrefix(httpStr, "POST ") {
	// 	return nil // Not an HTTP request
	// }

	f.l.Info("Processing HTTP request")

	// Create HTTP response
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 44\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"<html><body>Hello from Nebula!</body></html>"
	responseBytes := []byte(response)

	// Create TCP packet with HTTP response
	responsePacket, err := f.createTCPResponse(
		ipHeader.Dst, ipHeader.Src,
		tcpHeader.DstPort, tcpHeader.SrcPort,
		tcpHeader.AckNum,                       // Our seq = their ack
		tcpHeader.SeqNum+uint32(len(httpData)), // Our ack = their seq + data length
		responseBytes,
		TCPFlagACK|TCPFlagPSH, // ACK + PUSH
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP response: %w", err)
	}

	// Send the HTTP response

	f.sendPacketResponse(responsePacket, hostinfo, nb, packet, q)

	// Step 2: Send FIN packet to close the connection
	// Our sequence number is now incremented by the response length
	finPacket, err := f.createTCPResponse(
		ipHeader.Dst, ipHeader.Src,
		tcpHeader.DstPort, tcpHeader.SrcPort,
		tcpHeader.AckNum+uint32(len(responseBytes)), // Our seq after sending response
		tcpHeader.SeqNum+uint32(len(httpData)),      // Same ack number
		nil,                                         // No payload for FIN
		TCPFlagFIN|TCPFlagACK,                       // FIN + ACK
	)
	if err != nil {
		return fmt.Errorf("failed to create FIN packet: %w", err)
	}

	// Send the FIN packet
	f.sendPacketResponse(finPacket, hostinfo, nb, packet, q)
	return nil
}

func (f *Interface) handleTCPFin(ipHeader *ipv4.Header, tcpHeader *TCPHeader, hostinfo *HostInfo, nb []byte, packet []byte, q int) error {
	f.l.Info("Handling TCP FIN, sending FIN-ACK")

	// Send FIN-ACK response
	finAckPacket, err := f.createTCPResponse(
		ipHeader.Dst, ipHeader.Src,
		tcpHeader.DstPort, tcpHeader.SrcPort,
		tcpHeader.AckNum,
		tcpHeader.SeqNum+1,
		nil, // No payload
		TCPFlagFIN|TCPFlagACK,
	)
	if err != nil {
		return fmt.Errorf("failed to create FIN-ACK: %w", err)
	}

	f.sendPacketResponse(finAckPacket, hostinfo, nb, packet, q)
	return nil
}

func (f *Interface) sendSynAck(tcpState *TCPConnectionState, hostinfo *HostInfo, nb []byte, packet []byte, q int) error {
	synAckPacket, err := f.createSynAckPacket(
		tcpState.localIP,
		tcpState.remoteIP,
		tcpState.localPort,
		tcpState.remotePort,
		tcpState.localSeq,
		tcpState.remoteSeq,
	)
	if err != nil {
		return fmt.Errorf("failed to create SYN-ACK packet: %w", err)
	}

	f.sendPacketResponse(synAckPacket, hostinfo, nb, packet, q)
	return nil
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // Header length in 32-bit words
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
}

// TCP Flags
const (
	TCPFlagFIN = 1 << 0
	TCPFlagSYN = 1 << 1
	TCPFlagRST = 1 << 2
	TCPFlagPSH = 1 << 3
	TCPFlagACK = 1 << 4
	TCPFlagURG = 1 << 5
	TCPFlagECE = 1 << 6
	TCPFlagCWR = 1 << 7
)

func parseTCPHeader(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("TCP header too short: %d bytes", len(data))
	}

	header := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: (data[12] >> 4) & 0x0F, // Upper 4 bits
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}

	// Calculate actual header length in bytes
	headerLen := int(header.DataOffset * 4)
	if headerLen < 20 {
		return nil, fmt.Errorf("invalid TCP header length: %d", headerLen)
	}

	if len(data) < headerLen {
		return nil, fmt.Errorf("TCP packet too short for header length: %d", headerLen)
	}

	// Extract options if present
	if headerLen > 20 {
		header.Options = make([]byte, headerLen-20)
		copy(header.Options, data[20:headerLen])
	}

	return header, nil
}

func (h *TCPHeader) HasFlag(flag uint8) bool {
	return h.Flags&flag != 0
}

func (h *TCPHeader) HeaderLen() int {
	return int(h.DataOffset * 4)
}

func (h *TCPHeader) PayloadOffset() int {
	return h.HeaderLen()
}

// NebulaHTTPConn represents a TCP connection over Nebula
type NebulaHTTPConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	readBuf    *bytes.Buffer
	writeBuf   *bytes.Buffer
	writeChan  chan []byte
	readChan   chan []byte
	closed     bool
	closeOnce  sync.Once
	f          *Interface
	hostinfo   *HostInfo
	tcpState   *TCPConnectionState
	mu         sync.Mutex
	// Store Nebula packet context
	nb     []byte
	packet []byte
	q      int
}

// TCPConnectionState tracks the state of a TCP connection
type TCPConnectionState struct {
	localSeq   uint32
	remoteSeq  uint32
	localPort  uint16
	remotePort uint16
	localIP    net.IP
	remoteIP   net.IP
	state      string // "SYN_RECEIVED", "ESTABLISHED", "CLOSE_WAIT", etc.
}

// NebulaHTTPListener implements net.Listener for HTTP over Nebula
type NebulaHTTPListener struct {
	f           *Interface
	connections map[string]*NebulaHTTPConn
	connChan    chan net.Conn
	closed      bool
	closeOnce   sync.Once
	mu          sync.Mutex
}

// NewNebulaHTTPListener creates a new HTTP listener for Nebula
func NewNebulaHTTPListener(f *Interface) *NebulaHTTPListener {
	return &NebulaHTTPListener{
		f:           f,
		connChan:    make(chan net.Conn, 100),
		connections: make(map[string]*NebulaHTTPConn),
	}
}

// Accept implements net.Listener
func (l *NebulaHTTPListener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, fmt.Errorf("listener closed")
	}

	conn, ok := <-l.connChan
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}

	return conn, nil
}

// Close implements net.Listener
func (l *NebulaHTTPListener) Close() error {
	l.closeOnce.Do(func() {
		l.closed = true
		close(l.connChan)
	})
	return nil
}

// Addr implements net.Listener
func (l *NebulaHTTPListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 80}
}

// HandleNewConnection creates a new connection and sends it to the listener
func (l *NebulaHTTPListener) HandleNewConnection(ipHeader *ipv4.Header, tcpHeader *TCPHeader, hostinfo *HostInfo, nb []byte, packet []byte, q int) error {
	if l.closed {
		return fmt.Errorf("listener closed")
	}

	// Create TCP connection state
	tcpState := &TCPConnectionState{
		remoteSeq:  tcpHeader.SeqNum + 1,
		localSeq:   generateISN(),
		localPort:  tcpHeader.DstPort,
		remotePort: tcpHeader.SrcPort,
		localIP:    ipHeader.Dst,
		remoteIP:   ipHeader.Src,
		state:      "SYN_RECEIVED",
	}

	connKey := fmt.Sprintf("%s:%d-%s:%d", ipHeader.Src, tcpHeader.SrcPort, ipHeader.Dst, tcpHeader.DstPort)
	l.f.l.Infof("Handling New Connection: %s", connKey)

	// Create connection
	conn := &NebulaHTTPConn{
		localAddr:  &net.TCPAddr{IP: ipHeader.Dst, Port: int(tcpHeader.DstPort)},
		remoteAddr: &net.TCPAddr{IP: ipHeader.Src, Port: int(tcpHeader.SrcPort)},
		readChan:   make(chan []byte, 10),
		writeChan:  make(chan []byte, 10),
		f:          l.f,
		hostinfo:   hostinfo,
		tcpState:   tcpState,
		readBuf:    bytes.NewBuffer(nil),
		writeBuf:   bytes.NewBuffer(nil),
		// Store Nebula context
		nb:     nb,
		packet: packet,
		q:      q,
	}
	l.connections[connKey] = conn

	// Send SYN-ACK
	if err := l.f.sendSynAck(tcpState, hostinfo, nb, packet, q); err != nil {
		return err
	}

	// Increment our sequence number after sending SYN-ACK (SYN consumes 1 sequence number)
	tcpState.localSeq++

	// Send connection to listener
	select {
	case l.connChan <- conn:
		return nil
	default:
		return fmt.Errorf("connection queue full")
	}
}

// Implement net.Conn interface for NebulaHTTPConn
func (c *NebulaHTTPConn) Read(b []byte) (n int, err error) {
	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	// Wait for data from readChan
	select {
	case data := <-c.readChan:
		n = copy(b, data)
		if n < len(data) {
			// Put remaining data back
			remaining := make([]byte, len(data)-n)
			copy(remaining, data[n:])
			select {
			case c.readChan <- remaining:
			default:
				// Channel full, data lost
			}
		}
		return n, nil
	case <-time.After(30 * time.Second):
		return 0, fmt.Errorf("read timeout")
	}
	// l.Log.Info().Msgf("LN Read: %v", c.readBuf.Len())
	// c.mu.Lock()
	// defer c.mu.Unlock()
	// return c.readBuf.Read(b)
}

func (c *NebulaHTTPConn) Write(b []byte) (n int, err error) {
	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	// Send data through Nebula
	l.Log.Info().Msgf("Writing for NebulaHTTPConn (%d bytes), localSeq: %d, remoteSeq: %d\n%s", len(b), c.tcpState.localSeq, c.tcpState.remoteSeq, string(b))
	responsePacket, err := c.f.createTCPResponse(
		c.tcpState.localIP, c.tcpState.remoteIP,
		c.tcpState.localPort, c.tcpState.remotePort,
		c.tcpState.localSeq,
		c.tcpState.remoteSeq,
		b,
		TCPFlagACK|TCPFlagPSH,
	)
	if err != nil {
		return 0, err
	}

	c.f.sendPacketResponse(responsePacket, c.hostinfo, c.nb, c.packet, c.q)
	c.tcpState.localSeq += uint32(len(b))

	return len(b), nil
}

func (c *NebulaHTTPConn) Close() error {
	l.Log.Info().Msg("Closing Conn")
	c.closed = true
	c.closeOnce.Do(func() {
		close(c.readChan)
		close(c.writeChan)

		// Send FIN packet
		finPacket, err := c.f.createTCPResponse(
			c.tcpState.localIP, c.tcpState.remoteIP,
			c.tcpState.localPort, c.tcpState.remotePort,
			c.tcpState.localSeq,
			c.tcpState.remoteSeq,
			nil,
			TCPFlagFIN|TCPFlagACK,
		)
		if err == nil {
			c.f.sendPacketResponse(finPacket, c.hostinfo, c.nb, c.packet, c.q)
		}
	})
	return nil
}

func (c *NebulaHTTPConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *NebulaHTTPConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *NebulaHTTPConn) SetDeadline(t time.Time) error      { return nil }
func (c *NebulaHTTPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *NebulaHTTPConn) SetWriteDeadline(t time.Time) error { return nil }

// AddData adds incoming TCP data to the connection
func (c *NebulaHTTPConn) AddData(data []byte) {
	if !c.closed && len(data) > 0 {
		select {
		case c.readChan <- data:
		default:
			// Channel full, drop data
		}
	}
}

func (pl *NebulaHTTPListener) HandlePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, tcpData []byte) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	if pl.closed {
		return
	}

	connKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)

	conn, exists := pl.connections[connKey]
	l.Log.Info().Msgf("HandlePacket Connection: %s (%v)", connKey, exists)
	// if !exists {
	// 	l.Log.Info().Msgf("Creating new connection: %s", connKey)
	// 	conn = &NebulaHTTPConn{
	// 		localAddr:  &net.TCPAddr{IP: dstIP, Port: int(dstPort)},
	// 		remoteAddr: &net.TCPAddr{IP: srcIP, Port: int(srcPort)},
	// 		readBuf:    bytes.NewBuffer(nil),
	// 		writeBuf:   bytes.NewBuffer(nil),
	// 	}
	// 	pl.connections[connKey] = conn

	// 	// Send new connection to Accept()
	// 	select {
	// 	case pl.connChan <- conn:
	// 	default:
	// 		// Channel full, drop connection
	// 		delete(pl.connections, connKey)
	// 		return
	// 	}
	// }

	// Append TCP data to read buffer
	conn.mu.Lock()
	// conn.readBuf.Write(tcpData)
	// d := []byte{}
	// copy(d, tcpData)
	conn.AddData(tcpData)
	conn.tcpState.remoteSeq = conn.tcpState.remoteSeq + uint32(len(tcpData))

	conn.mu.Unlock()
}

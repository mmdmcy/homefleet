package discover

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mmdmcy/homefleet/internal/config"
)

const (
	beaconInterval = 2 * time.Second
	peerTTL        = 8 * time.Second
	// beaconWindow bounds how old (or how far in the future, for clock skew) a
	// beacon's timestamp may be before it is dropped as stale.
	beaconWindow = 60 * time.Second
)

// Beacon is the UDP discovery announcement. Beacons are authenticated: MAC is
// hex(HMAC-SHA256(token, canonical fields)) and TS/Nonce limit replay. A
// beacon without a valid MAC is ignored, so peers are only ever stored (and
// later sent the bearer token over HTTP) when they already hold the token.
type Beacon struct {
	Proto    string `json:"proto"`
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	HTTPPort int    `json:"http_port"`
	TS       int64  `json:"ts,omitempty"`    // unix seconds
	Nonce    string `json:"nonce,omitempty"` // 16 hex chars
	MAC      string `json:"mac,omitempty"`   // 64 hex chars
}

// canonical returns the bytes the MAC covers: every announced field, newline
// separated, so a verified beacon cannot have had any field altered.
func (b Beacon) canonical() string {
	return strings.Join([]string{
		b.Proto, b.ID, b.Hostname, b.OS,
		fmt.Sprintf("%d", b.HTTPPort), fmt.Sprintf("%d", b.TS), b.Nonce,
	}, "\n")
}

func beaconMAC(key []byte, b Beacon) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b.canonical()))
	return hex.EncodeToString(mac.Sum(nil))
}

// Sign stamps the beacon with the current time, a fresh nonce and the MAC.
func Sign(key []byte, b Beacon, now time.Time) (Beacon, error) {
	if len(key) == 0 {
		return Beacon{}, errors.New("discovery needs the shared token to sign beacons")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Beacon{}, err
	}
	b.TS = now.Unix()
	b.Nonce = hex.EncodeToString(nonce[:])
	b.MAC = beaconMAC(key, b)
	return b, nil
}

type Peer struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	IP       string    `json:"ip"`
	HTTPPort int       `json:"http_port"`
	Self     bool      `json:"self,omitempty"`
	SeenAt   time.Time `json:"seen_at"`
}

func (p Peer) BaseURL() string {
	return fmt.Sprintf("http://%s", net.JoinHostPort(p.IP, fmt.Sprintf("%d", p.HTTPPort)))
}

type Table struct {
	mu     sync.Mutex
	peers  map[string]Peer
	self   Beacon
	key    []byte
	nonces map[string]time.Time // nonce -> expiry, to drop replayed beacons
	warned bool
}

func NewTable(cfg config.Config) *Table {
	return &Table{
		peers:  map[string]Peer{},
		key:    []byte(cfg.Token),
		nonces: map[string]time.Time{},
		self: Beacon{
			Proto:    config.DefaultProto,
			ID:       cfg.DeviceID,
			Hostname: cfg.Hostname,
			OS:       cfg.OS,
			HTTPPort: cfg.HTTPPort,
		},
	}
}

// Verify reports whether a received beacon is authentic: well formed, carrying
// a MAC computed with this table's token, timestamped within beaconWindow of
// now, and not seen before (nonce). Anything else is silently dropped; the
// first unauthenticated beacon per table is noted once on stderr so an
// operator can tell "old version / different token" from "nothing on the LAN".
func (t *Table) Verify(b Beacon, now time.Time) bool {
	if b.Proto != config.DefaultProto || b.ID == "" || b.HTTPPort < 1 || len(t.key) == 0 {
		return false
	}
	want, err := hex.DecodeString(b.MAC)
	if err != nil || len(want) != sha256.Size || b.Nonce == "" {
		t.warnOnce(b.ID)
		return false
	}
	got, _ := hex.DecodeString(beaconMAC(t.key, b))
	if !hmac.Equal(got, want) {
		t.warnOnce(b.ID)
		return false
	}
	age := now.Sub(time.Unix(b.TS, 0))
	if age > beaconWindow || age < -beaconWindow {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for nonce, expiry := range t.nonces {
		if now.After(expiry) {
			delete(t.nonces, nonce)
		}
	}
	if _, seen := t.nonces[b.Nonce]; seen {
		return false
	}
	t.nonces[b.Nonce] = now.Add(beaconWindow)
	return true
}

func (t *Table) warnOnce(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.warned {
		return
	}
	t.warned = true
	fmt.Fprintf(os.Stderr, "homefleet: ignoring unauthenticated discovery beacon from %q (peer runs an old version or a different token)\n", id)
}

func (t *Table) Upsert(peer Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := peer.ID + "|" + peer.IP
	peer.SeenAt = time.Now()
	t.peers[key] = peer
}

func (t *Table) List() []Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	out := make([]Peer, 0, len(t.peers))
	for key, peer := range t.peers {
		if now.Sub(peer.SeenAt) > peerTTL {
			delete(t.peers, key)
			continue
		}
		out = append(out, peer)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].IP < out[j].IP
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (t *Table) Find(query string) (Peer, error) {
	matches := []Peer{}
	for _, peer := range t.List() {
		if peer.ID == query || peer.Hostname == query || peer.IP == query {
			matches = append(matches, peer)
		}
	}
	if len(matches) == 0 {
		return Peer{}, fmt.Errorf("peer %q not found (is the agent running on the LAN?)", query)
	}
	if len(matches) > 1 {
		return Peer{}, fmt.Errorf("multiple peers match %q; use --host", query)
	}
	return matches[0], nil
}

// SelfBeacon returns a freshly signed announcement for this device.
func (t *Table) SelfBeacon() (Beacon, error) {
	return Sign(t.key, t.self, time.Now())
}

func listenUDP(ctx context.Context, network string, addr string) (*net.UDPConn, error) {
	var lc net.ListenConfig
	lc.Control = reusePortControl
	pc, err := lc.ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("expected UDP connection")
	}
	return udp, nil
}

func RunBeacon(ctx context.Context, cfg config.Config, table *Table) error {
	conn, err := listenUDP(ctx, "udp4", fmt.Sprintf(":%d", cfg.BeaconPort))
	if err != nil {
		return fmt.Errorf("listen beacon: %w", err)
	}
	defer conn.Close()

	// Seed self so local /v1/peers is useful immediately.
	table.Upsert(Peer{
		ID:       cfg.DeviceID,
		Hostname: cfg.Hostname,
		OS:       cfg.OS,
		IP:       "127.0.0.1",
		HTTPPort: cfg.HTTPPort,
		Self:     true,
	})

	go receiveBeacons(ctx, conn, table, cfg.DeviceID)
	ticker := time.NewTicker(beaconInterval)
	defer ticker.Stop()

	broadcast := func() {
		table.Upsert(Peer{
			ID:       cfg.DeviceID,
			Hostname: cfg.Hostname,
			OS:       cfg.OS,
			IP:       "127.0.0.1",
			HTTPPort: cfg.HTTPPort,
			Self:     true,
		})
		beacon, err := table.SelfBeacon()
		if err != nil {
			return
		}
		payload, _ := json.Marshal(beacon)
		for _, dst := range broadcastAddrs(cfg.BeaconPort) {
			_, _ = conn.WriteToUDP(payload, dst)
		}
	}
	broadcast()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			broadcast()
		}
	}
}

func receiveBeacons(ctx context.Context, conn *net.UDPConn, table *Table, selfID string) {
	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		var beacon Beacon
		if err := json.Unmarshal(buf[:n], &beacon); err != nil {
			continue
		}
		if !table.Verify(beacon, time.Now()) {
			continue
		}
		table.Upsert(Peer{
			ID:       beacon.ID,
			Hostname: beacon.Hostname,
			OS:       beacon.OS,
			IP:       addr.IP.String(),
			HTTPPort: beacon.HTTPPort,
			Self:     selfID != "" && beacon.ID == selfID,
		})
	}
}

// ListenOnce collects authenticated beacons for duration. The token is needed
// to verify them; without it nothing can be trusted, so it is an error.
func ListenOnce(ctx context.Context, token string, beaconPort int, duration time.Duration) ([]Peer, error) {
	if token == "" {
		return nil, errors.New("missing token: discovery beacons are authenticated with HOMEFLEET_TOKEN or DALE_TOKEN")
	}
	cfg := config.Config{
		Token:      token,
		DeviceID:   "listener",
		Hostname:   "listener",
		OS:         runtime.GOOS,
		HTTPPort:   0,
		BeaconPort: beaconPort,
	}
	table := NewTable(cfg)
	conn, err := listenUDP(ctx, "udp4", fmt.Sprintf(":%d", beaconPort))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	listenCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	go receiveBeacons(listenCtx, conn, table, "")
	<-listenCtx.Done()
	return table.List(), nil
}

func broadcastAddrs(port int) []*net.UDPAddr {
	addrs := []*net.UDPAddr{{IP: net.IPv4bcast, Port: port}}
	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}
	seen := map[string]bool{"255.255.255.255": true}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifaceAddrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			bcast := broadcastIP(ipnet)
			if bcast == nil {
				continue
			}
			key := bcast.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			addrs = append(addrs, &net.UDPAddr{IP: bcast, Port: port})
		}
	}
	return addrs
}

func broadcastIP(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	mask := ipnet.Mask
	if ip == nil || len(mask) != 4 {
		return nil
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast
}

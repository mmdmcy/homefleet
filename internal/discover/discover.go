package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/mmdmcy/homefleet/internal/config"
)

const (
	beaconInterval = 2 * time.Second
	peerTTL        = 8 * time.Second
)

type Beacon struct {
	Proto    string `json:"proto"`
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	HTTPPort int    `json:"http_port"`
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
	mu    sync.Mutex
	peers map[string]Peer
	self  Beacon
}

func NewTable(cfg config.Config) *Table {
	return &Table{
		peers: map[string]Peer{},
		self: Beacon{
			Proto:    config.DefaultProto,
			ID:       cfg.DeviceID,
			Hostname: cfg.Hostname,
			OS:       cfg.OS,
			HTTPPort: cfg.HTTPPort,
		},
	}
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

func (t *Table) SelfBeacon() Beacon {
	return t.self
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
		payload, _ := json.Marshal(table.SelfBeacon())
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
		if beacon.Proto != config.DefaultProto || beacon.ID == "" || beacon.HTTPPort < 1 {
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

func ListenOnce(ctx context.Context, beaconPort int, duration time.Duration) ([]Peer, error) {
	cfg := config.Config{
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

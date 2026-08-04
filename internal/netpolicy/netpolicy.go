package netpolicy

import (
	"net"
	"strings"
)

var tailscaleNetworks = []*net.IPNet{
	mustCIDR("100.64.0.0/10"),
	mustCIDR("fd7a:115c:a1e0::/48"),
}

var privateNetworks = []*net.IPNet{
	mustCIDR("10.0.0.0/8"),
	mustCIDR("172.16.0.0/12"),
	mustCIDR("192.168.0.0/16"),
	mustCIDR("169.254.0.0/16"),
	mustCIDR("fc00::/7"),
	mustCIDR("fe80::/10"),
}

func Allowed(ip net.IP, scope string, extraCIDRs []string) bool {
	if ip == nil {
		return false
	}
	if !allowedByScope(ip, scope) {
		return false
	}
	if len(extraCIDRs) == 0 {
		return true
	}
	for _, raw := range extraCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func allowedByScope(ip net.IP, scope string) bool {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "loopback", "local":
		return ip.IsLoopback()
	case "tailnet", "tailscale":
		return ip.IsLoopback() || isTailscaleIP(ip)
	case "public", "all", "any":
		return true
	default:
		return ip.IsLoopback() || isPrivateNetworkIP(ip)
	}
}

func isTailscaleIP(ip net.IP) bool {
	for _, network := range tailscaleNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateNetworkIP(ip net.IP) bool {
	if isTailscaleIP(ip) {
		return true
	}
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return network
}

func ParseIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

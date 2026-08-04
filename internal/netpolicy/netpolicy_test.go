package netpolicy

import (
	"net"
	"testing"
)

func TestAllowedPrivate(t *testing.T) {
	cases := []struct {
		ip    string
		scope string
		want  bool
	}{
		{"127.0.0.1", "private", true},
		{"192.168.1.10", "private", true},
		{"10.0.0.2", "private", true},
		{"100.64.1.1", "private", true},
		{"8.8.8.8", "private", false},
		{"8.8.8.8", "public", true},
		{"8.8.8.8", "loopback", false},
		{"127.0.0.1", "loopback", true},
		{"100.64.1.1", "tailnet", true},
		{"192.168.1.10", "tailnet", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		got := Allowed(ip, tc.scope, nil)
		if got != tc.want {
			t.Fatalf("%s scope=%s got %v want %v", tc.ip, tc.scope, got, tc.want)
		}
	}
}

func TestAllowCIDRs(t *testing.T) {
	ip := net.ParseIP("192.168.1.50")
	if !Allowed(ip, "private", []string{"192.168.1.0/24"}) {
		t.Fatal("expected allow")
	}
	if Allowed(ip, "private", []string{"10.0.0.0/8"}) {
		t.Fatal("expected deny when extra CIDR does not match")
	}
}

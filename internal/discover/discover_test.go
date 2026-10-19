package discover

import (
	"testing"
	"time"

	"github.com/mmdmcy/homefleet/internal/config"
)

func testTable(token string) *Table {
	return NewTable(config.Config{Token: token, DeviceID: "a", Hostname: "a", OS: "linux", HTTPPort: 7350})
}

func TestVerifyAcceptsSignedBeacon(t *testing.T) {
	now := time.Now()
	sender, receiver := testTable("secret"), testTable("secret")
	b, err := Sign(sender.key, sender.self, now)
	if err != nil {
		t.Fatal(err)
	}
	if b.MAC == "" || b.Nonce == "" || b.TS == 0 {
		t.Fatalf("beacon not stamped: %+v", b)
	}
	if !receiver.Verify(b, now) {
		t.Fatal("valid beacon rejected")
	}
	if receiver.Verify(b, now.Add(time.Second)) {
		t.Fatal("replayed beacon (same nonce) accepted")
	}
}

func TestVerifyDropsWrongKey(t *testing.T) {
	now := time.Now()
	sender, receiver := testTable("secret"), testTable("other")
	b, err := Sign(sender.key, sender.self, now)
	if err != nil {
		t.Fatal(err)
	}
	if receiver.Verify(b, now) {
		t.Fatal("beacon signed with another token accepted")
	}
	tampered := b
	tampered.HTTPPort = 1
	if testTable("secret").Verify(tampered, now) {
		t.Fatal("tampered beacon accepted")
	}
}

func TestVerifyDropsStaleAndUnsigned(t *testing.T) {
	now := time.Now()
	sender := testTable("secret")
	b, err := Sign(sender.key, sender.self, now.Add(-2*beaconWindow))
	if err != nil {
		t.Fatal(err)
	}
	if testTable("secret").Verify(b, now) {
		t.Fatal("stale beacon accepted")
	}
	if testTable("secret").Verify(sender.self, now) {
		t.Fatal("unsigned (old-format) beacon accepted")
	}
	if _, err := Sign(nil, sender.self, now); err == nil {
		t.Fatal("signing without a token should fail")
	}
}

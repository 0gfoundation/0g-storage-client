package indexer

import "testing"

func TestIsNonRoutableIP(t *testing.T) {
	// Regression for #143: the indexer's startup IP-geo lookup must
	// short-circuit for any IP where ipinfo.io has nothing useful to
	// say, so a slow / blocked external network can't hang startup.
	cases := []struct {
		ip   string
		want bool
		desc string
	}{
		{"127.0.0.1", true, "IPv4 loopback"},
		{"::1", true, "IPv6 loopback"},
		{"10.0.0.1", true, "RFC1918 10/8"},
		{"172.16.0.1", true, "RFC1918 172.16/12"},
		{"172.31.255.255", true, "RFC1918 172.31 edge"},
		{"192.168.1.1", true, "RFC1918 192.168/16"},
		{"169.254.1.1", true, "link-local IPv4"},
		{"fe80::1", true, "link-local IPv6"},
		{"0.0.0.0", true, "unspecified"},
		{"8.8.8.8", false, "public DNS"},
		{"1.1.1.1", false, "public"},
		{"172.32.0.1", false, "outside RFC1918 172.16/12"},
		{"not-an-ip", false, "unparseable"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			got := isNonRoutableIP(c.ip)
			if got != c.want {
				t.Errorf("isNonRoutableIP(%q) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

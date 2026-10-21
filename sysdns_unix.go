//go:build !windows

package dac

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

// systemDNSServers reads the nameserver lines of /etc/resolv.conf.
func systemDNSServers() ([]netip.Addr, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, a.WithZone(""))
			}
		}
	}
	return out, sc.Err()
}

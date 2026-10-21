//go:build windows

package dac

import (
	"net/netip"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemDNSServers returns the DNS servers of the network adapters that are up,
// in adapter order, as Windows itself uses them.
func systemDNSServers() ([]netip.Addr, error) {
	size := uint32(15000)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, aa, &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || i == 2 {
			return nil, os.NewSyscallError("GetAdaptersAddresses", err)
		}
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
			a, ok := netip.AddrFromSlice(d.Address.IP())
			if !ok {
				continue
			}
			a = a.Unmap()
			// Windows lists fec0:0:0:ffff::1-3 as placeholder servers.
			if b := a.As16(); a.Is6() && b[0] == 0xfe && b[1] == 0xc0 {
				continue
			}
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out, nil
}

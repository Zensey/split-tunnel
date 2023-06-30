package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/kmahyyg/go-network-compo/wintypes"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// use network order (big endian)
func Inet_aton_(ip string) []byte {
	long := binary.BigEndian.Uint32(net.ParseIP(ip).To4())
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, long)
	return b
}

func fillArrayWithZeros(currentArray []byte) {
	for i := range currentArray {
		currentArray[i] = 0
	}
}

func getProcessName(pid uint32) string {
	const MAX_PATH = 260

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(hProcess)

	if hProcess > 0 {
		var szModName [MAX_PATH]uint16
		if err1 := windows.GetModuleFileNameEx(hProcess, 0, &szModName[0], MAX_PATH); err1 != nil {
			fmt.Printf("Error: %v\n", syscall.GetLastError())
			return ""
		}
		return syscall.UTF16ToString(szModName[:])
	}
	return ""
}

// get the ip of interface used for forwarding to prefered gateway
func getRedirectIP() (string, error) {
	routingTable, err := wintypes.GetIPForwardTable2(wintypes.AddressFamily(wintypes.AF_INET))
	if err != nil {
		return "", fmt.Errorf("failed to get adapter addresses: %w", err)
	}

	for i := range routingTable {
		singleIpFwdRow := &routingTable[i]

		idx := singleIpFwdRow.InterfaceIndex
		dest := singleIpFwdRow.DestinationPrefix.RawPrefix.Addr().String() + "/" + strconv.Itoa(int(singleIpFwdRow.DestinationPrefix.PrefixLength))
		gw := singleIpFwdRow.NextHop.Addr().String()

		if dest == "0.0.0.0/0" && gw != "0.0.0.0" {
			fmt.Println(idx, dest, gw)

			out, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
			if err != nil {
				return "", fmt.Errorf("failed to get adapter addresses: %w", err)

			}

			for i, o := range out {
				if idx == o.IfIndex {
					fmt.Println(i, o.IfIndex, o.FirstUnicastAddress.Address.IP().String())
					return o.FirstUnicastAddress.Address.IP().String(), nil
				}
			}
		}
	}
	return "", nil
}

package main

/*
#include "../sys/ioctl.h"
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const USB_CONTROL_INTERFACE_WIN32_W = `\\.\Splitter`

type Request struct {
	pid    uint64
	result uint8
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
		fmt.Println(err)
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

// use network order (big endian)
func ip2bytes(ip string) []byte {
	var long uint32
	b := make([]byte, 4)
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	binary.BigEndian.PutUint32(b, long)

	return b
}

func main() {
	defer func() {
		fmt.Println("Press the Enter Key to stop anytime")
		fmt.Scanln()
	}()

	name, _ := windows.UTF16FromString(USB_CONTROL_INTERFACE_WIN32_W)
	dev, err := syscall.CreateFile(
		&name[0],
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_SYSTEM|syscall.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		fmt.Println("err", err)
		return
	}

	gw := ip2bytes("172.20.37.103")
	log.Printf("ioctl > request > set config", (gw))
	err = syscall.DeviceIoControl(dev, C.IOCTL_SPLITTER_CONFIG, &gw[0], 4, nil, 0, nil, nil)
	if err != nil {
		log.Println("err", err)
		return
	}

	var bytesOut uint32
	buf := make([]byte, 100)

	for {
		fillArrayWithZeros(buf)
		log.Printf("ioctl > wait req")
		err = syscall.DeviceIoControl(dev, C.IOCTL_SPLITTER_REQUEST, nil, 0, &buf[0], uint32(len(buf)), &bytesOut, nil)
		if err != nil {
			log.Println("err", err)
			return
		}
		req := (*Request)(unsafe.Pointer(&buf[0]))

		procName := getProcessName(uint32(req.pid))
		log.Println("req > proc >", procName, " pid:", req)

		log.Println("ioctl > reply")
		rep := (*Request)(unsafe.Pointer(&buf[0]))
		if strings.HasSuffix(strings.ToLower(procName), "msedge.exe") {
			rep.result = 1
		}
		err = syscall.DeviceIoControl(dev, C.IOCTL_SPLITTER_REPLY, &buf[0], uint32(len(buf)), nil, 0, &bytesOut, nil)
		if err != nil {
			log.Println("err", err)
			return
		}
	}
}

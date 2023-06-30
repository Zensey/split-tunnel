package main

/*
#include "../sys/ioctl.h"
*/
import "C"

import (
	"fmt"
	"log"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	USB_CONTROL_INTERFACE_WIN32_W = `\\.\Splitter`
)

type Request struct {
	pid    uint64
	result uint8
}

func main() {
	redirectIP, err := getRedirectIP()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("redirectIP:", redirectIP)

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

	redirectIPBytes := Inet_aton_(redirectIP)
	log.Println("ioctl > request > set config", (redirectIPBytes))
	err = syscall.DeviceIoControl(dev, C.IOCTL_SPLITTER_CONFIG, &redirectIPBytes[0], 4, nil, 0, nil, nil)
	if err != nil {
		log.Println("err", err)
		return
	}

	var bytesOut uint32
	buf := make([]byte, 100)
	req := (*Request)(unsafe.Pointer(&buf[0]))
	for {
		fillArrayWithZeros(buf)
		// log.Printf("ioctl > wait req")
		err = syscall.DeviceIoControl(dev, C.IOCTL_SPLITTER_REQUEST, nil, 0, &buf[0], uint32(len(buf)), &bytesOut, nil)
		if err != nil {
			return
		}

		procName := getProcessName(uint32(req.pid))
		if procName != "" {
			log.Println("req > exe >", procName, " pid:", req.pid)
		} else {
			log.Println("req > exe (unknown) > pid:", req.pid)
		}

		//log.Println("reply > ")
		rep := (*Request)(unsafe.Pointer(&buf[0]))
		if strings.HasSuffix(strings.ToLower(procName), "msedge.exe") {
			rep.result = 1
		}
		if rep.result > 0 {
			log.Println("reply > allow")
		} else {
			log.Println("reply > deny")
		}
		err = syscall.DeviceIoControl(dev, C.IOCTL_SPLITTER_REPLY, &buf[0], uint32(len(buf)), nil, 0, &bytesOut, nil)
		if err != nil {
			log.Println("err", err)
			return
		}
	}
}

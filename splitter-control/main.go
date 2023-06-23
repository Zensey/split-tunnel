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
		name := syscall.UTF16ToString(szModName[:])
		return name
	}
	return ""
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

	var bytesOut uint32
	buf := make([]byte, 100)

	for {
		fillArrayWithZeros(buf)
		log.Printf("ioctl > request")
		err = syscall.DeviceIoControl(dev, C.IOCTL_SPLITTER_REQUEST, nil, 0, &buf[0], uint32(len(buf)), &bytesOut, nil)
		if err != nil {
			log.Println("err", err)
			return
		}
		req := (*Request)(unsafe.Pointer(&buf[0]))
		log.Println("request > pid:", req)

		procName := getProcessName(uint32(req.pid))
		log.Println("proc >", procName)

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

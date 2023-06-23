package main

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestStructures(t *testing.T) {
	buf := make([]byte, 100)
	req := (*Request)(unsafe.Pointer(&buf[0]))
	req.pid = 12345
	fmt.Println("request", req)
	fmt.Println("request", buf)

	rep := (*Request)(unsafe.Pointer(&buf[0]))
	rep.result = 1
	fmt.Println("request", buf)
}

package main

import (
	"fmt"
	"unsafe"

	"github.com/oarkflow/permission/utils"
)

func main() {
	s1 := "/coding/:wid/:eid/request-abandon POST /coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST"
	s2 := "/coding/:wid/:eid/request-abandon POST /coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST/coding/:wid/:eid/request-abandon POST"
	str1TotalSize := unsafe.Sizeof(s1) + uintptr(len(s1))
	i64S1 := utils.ToInt64(s1)
	i64S2 := utils.ToInt64(s2)
	fmt.Printf("Equal %v\n", i64S1 == i64S2)
	fmt.Printf("Size of string: %d bytes\n", unsafe.Sizeof(i64S1))
	fmt.Printf("Size of int64: %d bytes\n", str1TotalSize)
}

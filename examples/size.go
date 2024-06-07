package main

import (
	"github.com/oarkflow/permission/utils"
)

type TenantPrincipal struct {
	TenantID             string
	PrincipalID          string
	RoleID               string
	NamespaceID          string
	ScopeID              string
	CanManageDescendants bool
}

func UnmarshalTenantPrincipal(data []byte) TenantPrincipal {
	offset := 0
	var tp TenantPrincipal
	tp.TenantID, offset = readString(data, offset)
	tp.PrincipalID, offset = readString(data, offset)
	tp.RoleID, offset = readString(data, offset)
	tp.NamespaceID, offset = readString(data, offset)
	tp.ScopeID, offset = readString(data, offset)
	tp.CanManageDescendants = data[offset] == 1

	return tp
}

func readString(data []byte, offset int) (string, int) {
	length := int(data[offset]) | int(data[offset+1])<<8
	offset += 2
	return utils.FromByte(data[offset : offset+length]), offset + length
}

// MarshalTenantPrincipal encodes a TenantPrincipal into a binary string.
func MarshalTenantPrincipal(tp TenantPrincipal) ([]byte, error) {
	buffer := make([]byte, 0, 2*5+len(tp.TenantID)+len(tp.PrincipalID)+len(tp.RoleID)+len(tp.NamespaceID)+len(tp.ScopeID)+1)
	buffer = writeString(buffer, tp.TenantID)
	buffer = writeString(buffer, tp.PrincipalID)
	buffer = writeString(buffer, tp.RoleID)
	buffer = writeString(buffer, tp.NamespaceID)
	buffer = writeString(buffer, tp.ScopeID)
	if tp.CanManageDescendants {
		buffer = append(buffer, 1)
	} else {
		buffer = append(buffer, 0)
	}
	return buffer, nil
}

func writeString(buffer []byte, s string) []byte {
	length := uint16(len(s))
	buffer = append(buffer, byte(length), byte(length>>8))
	buffer = append(buffer, s...)
	return buffer
}

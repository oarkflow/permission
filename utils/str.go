package utils

import (
	"fmt"
	"hash/fnv"
	"strings"
)

func ToString(val any) string {
	switch val := val.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case nil:
		return ""
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

func ToInt64(s string) uint64 {
	ft := fnv.New64()
	_, _ = ft.Write([]byte(s))
	return ft.Sum64()
}

func MatchResource(value, pattern string) bool {
	vIndex, pIndex := 0, 0
	vLen, pLen := len(value), len(pattern)

	for pIndex < pLen {
		if pattern[pIndex] == '*' {
			// If '*' is the last character in the pattern, it matches everything
			if pIndex == pLen-1 {
				return true
			}

			// Find the next character in pattern after '*'
			nextChar := pattern[pIndex+1]

			// If the next character is '*', skip it
			if nextChar == '*' {
				pIndex++
				continue
			}

			// Find the next occurrence of the character after '*' in the value
			nextIndex := strings.IndexByte(value[vIndex:], nextChar)

			// If the character is not found, no match
			if nextIndex == -1 {
				return false
			}

			// Move the value index to the next occurrence of the character
			vIndex += nextIndex
		} else if pIndex < pLen && vIndex < vLen && (pattern[pIndex] == value[vIndex] || pattern[pIndex] == ':') {
			// If pattern part matches value part or is a parameter, move to the next parts
			vIndex++
			pIndex++
			// If pattern part is a parameter, skip it in the value
			if pattern[pIndex-1] == ':' {
				// Find the end of the parameter segment
				endIndex := pIndex
				for endIndex < pLen && pattern[endIndex] != '/' {
					endIndex++
				}
				// Skip the parameter segment in the value
				for vIndex < vLen && value[vIndex] != '/' {
					vIndex++
				}
				// Move pattern index to the end of the parameter segment
				pIndex = endIndex
			}
		} else {
			return false
		}
	}

	// If both value and pattern are exhausted, return true
	return vIndex == vLen && pIndex == pLen
}

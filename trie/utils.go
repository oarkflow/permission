package trie

import (
	"github.com/oarkflow/pool"
)

var (
	dataSlice1 = pool.NewSlicePool[*Data](100)
)

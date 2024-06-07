package v2

import (
	"github.com/oarkflow/pool"

	"github.com/oarkflow/permission/trie"
)

var (
	stringSlice        = pool.NewSlicePool[string](100)
	principalRoleSlice = pool.NewSlicePool[*trie.Data](100)
)

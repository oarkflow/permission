package permission

import (
	"github.com/oarkflow/pool"
)

var (
	stringSlice        = pool.NewSlicePool[string](100)
	principalRoleSlice = pool.NewSlicePool[TenantPrincipal](100)
)

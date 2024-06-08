package v1

import (
	"github.com/oarkflow/permission/utils"
)

var (
	stringSlice        = utils.NewSlicePool[string](100)
	principalRoleSlice = utils.NewSlicePool[TenantPrincipal](100)
)

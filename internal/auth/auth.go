// Package auth authenticates IPC peers via SO_PEERCRED and maps them to
// roles using group membership.
//
// Roles:
//   - admin:    uid 0, or a member of the admin group (default "wheel").
//   - operator: a member of the operator group (default "wgm"), or admin.
//   - none:     anyone else (only "ping" is answered).
package auth

import (
	"fmt"
	"os/user"
	"strconv"

	"github.com/cmerk2021/wgm/internal/api"
)

// Peer identifies the process on the other end of a socket.
type Peer struct {
	UID uint32
	GID uint32
	PID int32
}

// GroupLookup returns the supplementary group IDs of a user.
type GroupLookup func(uid uint32) ([]uint32, error)

// SystemGroups uses the system user database (NSS when built with cgo).
func SystemGroups(uid uint32) ([]uint32, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(ids))
	for _, s := range ids {
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out, nil
}

// Authorizer maps peers to roles.
type Authorizer struct {
	OperatorGroup string
	AdminGroup    string
	operatorGID   int64 // -1 when the group does not exist
	adminGID      int64
	Groups        GroupLookup
}

// NewAuthorizer resolves group names. Missing groups are not an error:
// they simply grant nobody that role (root is always admin).
func NewAuthorizer(operatorGroup, adminGroup string, lookup GroupLookup) *Authorizer {
	a := &Authorizer{OperatorGroup: operatorGroup, AdminGroup: adminGroup, operatorGID: -1, adminGID: -1, Groups: lookup}
	if g, err := user.LookupGroup(operatorGroup); err == nil {
		if n, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			a.operatorGID = int64(n)
		}
	}
	if g, err := user.LookupGroup(adminGroup); err == nil {
		if n, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			a.adminGID = int64(n)
		}
	}
	return a
}

// NewAuthorizerWithGIDs is used by tests and callers that resolved GIDs.
func NewAuthorizerWithGIDs(operatorGID, adminGID int64, lookup GroupLookup) *Authorizer {
	return &Authorizer{OperatorGroup: "operators", AdminGroup: "admins", operatorGID: operatorGID, adminGID: adminGID, Groups: lookup}
}

// OperatorGID returns the operator group ID or -1.
func (a *Authorizer) OperatorGID() int64 { return a.operatorGID }

// RoleOf determines a peer's role. Lookup failures fail closed.
func (a *Authorizer) RoleOf(p Peer) api.Role {
	if p.UID == 0 {
		return api.RoleAdmin
	}
	groups := map[int64]bool{int64(p.GID): true}
	if a.Groups != nil {
		if gs, err := a.Groups(p.UID); err == nil {
			for _, g := range gs {
				groups[int64(g)] = true
			}
		}
	}
	if a.adminGID >= 0 && groups[a.adminGID] {
		return api.RoleAdmin
	}
	if a.operatorGID >= 0 && groups[a.operatorGID] {
		return api.RoleOperator
	}
	return api.RoleNone
}

// required is the static authorization table. Operations not listed are
// unknown and rejected.
var required = map[string]api.Role{
	api.OpPing:            api.RoleNone,
	api.OpListTunnels:     api.RoleOperator,
	api.OpGetTunnel:       api.RoleOperator,
	api.OpGetKillSwitch:   api.RoleOperator,
	api.OpGetPolicy:       api.RoleOperator,
	api.OpEvents:          api.RoleOperator,
	api.OpMetrics:         api.RoleOperator,
	api.OpDiagnostics:     api.RoleOperator,
	api.OpConnect:         api.RoleOperator,
	api.OpDisconnect:      api.RoleOperator,
	api.OpRescan:          api.RoleOperator,
	api.OpSetTunnelPolicy: api.RoleOperator, // ownership/autostart changes additionally need admin
	api.OpSetKillSwitch:   api.RoleAdmin,
	api.OpSetMonitoring:   api.RoleAdmin,
}

// Required returns the role needed for op and whether op is known.
func Required(op string) (api.Role, bool) {
	r, ok := required[op]
	return r, ok
}

// Ops returns the allowlisted operations and their required roles.
func Ops() map[string]api.Role {
	out := make(map[string]api.Role, len(required))
	for k, v := range required {
		out[k] = v
	}
	return out
}

func rank(r api.Role) int {
	switch r {
	case api.RoleAdmin:
		return 2
	case api.RoleOperator:
		return 1
	}
	return 0
}

// Allows reports whether have satisfies need.
func Allows(have, need api.Role) bool { return rank(have) >= rank(need) }

// Check returns a forbidden error if role is insufficient for op.
func Check(role api.Role, op string) *api.Error {
	need, ok := Required(op)
	if !ok {
		return api.Errf(api.CodeUnknownOp, fmt.Sprintf("unknown operation %q", op))
	}
	if !Allows(role, need) {
		return api.Errf(api.CodeForbidden, fmt.Sprintf("operation %s requires the %s role (you have %s)", op, need, role))
	}
	return nil
}

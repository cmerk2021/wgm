package auth

import (
	"errors"
	"testing"

	"github.com/cmerk2021/wgm/internal/api"
)

func lookup(m map[uint32][]uint32) GroupLookup {
	return func(uid uint32) ([]uint32, error) {
		g, ok := m[uid]
		if !ok {
			return nil, errors.New("no such user")
		}
		return g, nil
	}
}

func TestRoleOf(t *testing.T) {
	a := NewAuthorizerWithGIDs(900, 10, lookup(map[uint32][]uint32{
		1000: {1000, 900},     // operator
		1001: {1001, 10, 900}, // admin (wheel)
		1002: {1002},          // nobody special
	}))
	cases := []struct {
		p    Peer
		want api.Role
	}{
		{Peer{UID: 0, GID: 0}, api.RoleAdmin},
		{Peer{UID: 1000, GID: 1000}, api.RoleOperator},
		{Peer{UID: 1001, GID: 1001}, api.RoleAdmin},
		{Peer{UID: 1002, GID: 1002}, api.RoleNone},
		{Peer{UID: 1003, GID: 900}, api.RoleOperator}, // primary gid from SO_PEERCRED
		{Peer{UID: 4242, GID: 4242}, api.RoleNone},    // lookup fails: fail closed
	}
	for _, c := range cases {
		if got := a.RoleOf(c.p); got != c.want {
			t.Errorf("%+v: got %s want %s", c.p, got, c.want)
		}
	}
}

func TestMissingGroupsGrantNothing(t *testing.T) {
	a := NewAuthorizerWithGIDs(-1, -1, lookup(map[uint32][]uint32{1000: {0, 1, 2}}))
	if r := a.RoleOf(Peer{UID: 1000, GID: 1000}); r != api.RoleNone {
		t.Fatalf("got %s", r)
	}
	if r := a.RoleOf(Peer{UID: 0}); r != api.RoleAdmin {
		t.Fatal("root must be admin")
	}
}

func TestCheck(t *testing.T) {
	if e := Check(api.RoleNone, api.OpPing); e != nil {
		t.Fatal(e)
	}
	if e := Check(api.RoleNone, api.OpListTunnels); e == nil || e.Code != api.CodeForbidden {
		t.Fatal("non-members must not list tunnels")
	}
	if e := Check(api.RoleOperator, api.OpConnect); e != nil {
		t.Fatal(e)
	}
	if e := Check(api.RoleOperator, api.OpSetKillSwitch); e == nil || e.Code != api.CodeForbidden {
		t.Fatal("kill switch changes require admin")
	}
	if e := Check(api.RoleAdmin, api.OpSetKillSwitch); e != nil {
		t.Fatal(e)
	}
	if e := Check(api.RoleAdmin, "exec"); e == nil || e.Code != api.CodeUnknownOp {
		t.Fatal("unknown ops must be rejected even for admin")
	}
	for op := range Ops() {
		if _, ok := Required(op); !ok {
			t.Fatal(op)
		}
	}
}

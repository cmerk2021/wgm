package ipc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"

	"github.com/cmerk2021/wgm/internal/auth"
)

// PeerCred reads SO_PEERCRED from a Unix socket connection. The kernel
// records the credentials at connect() time, so they cannot be forged by
// the client.
func PeerCred(c net.Conn) (auth.Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return auth.Peer{}, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return auth.Peer{}, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return auth.Peer{}, err
	}
	if serr != nil {
		return auth.Peer{}, serr
	}
	return auth.Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

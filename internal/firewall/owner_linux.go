package firewall

import (
	"errors"
	"io/fs"
	"syscall"
)

func checkOwnership(st fs.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine boot policy ownership")
	}
	if sys.Uid != 0 {
		return errors.New("boot policy file is not owned by root")
	}
	if st.Mode().Perm()&0o022 != 0 {
		return errors.New("boot policy file is writable by group or others")
	}
	if !st.Mode().IsRegular() {
		return errors.New("boot policy is not a regular file")
	}
	return nil
}

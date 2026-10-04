// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yuya Uwatoko

package bridge

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

var lockFiles []*os.File // kept open (and locked) until the process exits

// ListenSocket creates <dir>/bridge.sock per Bridge API §2: dir must be (or is created as) a 0700 directory owned
// by this user; a stale socket owned by this user is removed; the socket is created with mode 0600.
func ListenSocket(dir string) (net.Listener, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm() != 0o700 || !ok || int(sys.Uid) != os.Getuid() {
		return nil, "", fmt.Errorf("runtime dir %s must be a 0700 directory owned by uid %d", dir, os.Getuid())
	}
	// One Bridge per runtime dir: an exclusive lock held for the process lifetime makes any existing socket
	// provably stale before it is replaced (a second instance refuses to start instead of stealing it).
	lf, err := os.OpenFile(filepath.Join(dir, "bridge.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, "", err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lf.Close()
		return nil, "", fmt.Errorf("another bridge holds %s", dir)
	}
	lockFiles = append(lockFiles, lf)
	path := filepath.Join(dir, "bridge.sock")
	if fi, err := os.Lstat(path); err == nil {
		s, ok := fi.Sys().(*syscall.Stat_t)
		if fi.Mode()&os.ModeSocket == 0 || !ok || int(s.Uid) != os.Getuid() {
			return nil, "", fmt.Errorf("%s exists and is not our socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, "", err
		}
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, "", err
	}
	return ln, path, nil
}

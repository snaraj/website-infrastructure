//go:build linux

package server

import (
	"io/fs"
	"syscall"
)

// mediaFileHasMultipleLinks rejects an inode reachable by another Linux path,
// preventing originals or staging bytes from being hard-linked into delivery.
// A missing native stat shape fails closed on the production operating system.
func mediaFileHasMultipleLinks(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink != 1
}

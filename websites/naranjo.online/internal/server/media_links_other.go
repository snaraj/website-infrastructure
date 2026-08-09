//go:build !linux

package server

import "io/fs"

// mediaFileHasMultipleLinks is a portability shim for development tests. Media
// enablement is accepted only on the Linux production target, where the inode
// link-count check in media_links_linux.go is enforced.
func mediaFileHasMultipleLinks(_ fs.FileInfo) bool {
	return false
}

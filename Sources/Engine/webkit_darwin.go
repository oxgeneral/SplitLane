package process

/*
#include <dlfcn.h>
#include <sys/types.h>

static pid_t webkit_responsible_pid(pid_t pid) {
    pid_t (*lookup)(pid_t) = dlsym(RTLD_DEFAULT, "responsibility_get_pid_responsible_for_pid");
    return lookup == NULL ? 0 : lookup(pid);
}
*/
import "C"

import "strings"

func resolveWebKitOwner(pid uint32, path string) string {
	return resolveAppOwner(pid, path, func(p uint32) uint32 {
		owner := C.webkit_responsible_pid(C.pid_t(p))
		if owner <= 1 {
			return 0
		}
		return uint32(owner)
	}, getExecPathFromPID)
}

func resolveAppOwner(
	pid uint32,
	path string,
	responsiblePID func(uint32) uint32,
	execPath func(uint32) (string, error),
) string {
	if path == "" || strings.Contains(path, ".app/") {
		return path
	}

	// shortcut: this macOS SPI may be absent, in which case XPC/child processes keep their own identity.
	owner := responsiblePID(pid)
	if owner <= 1 || owner == pid {
		return path
	}
	ownerPath, err := execPath(owner)
	if err == nil && strings.Contains(ownerPath, ".app/") {
		return ownerPath
	}
	return path
}

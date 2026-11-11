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
	if !strings.HasSuffix(path, "/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking") {
		return path
	}

	// shortcut: this macOS SPI may be absent, in which case WebKit keeps its own identity.
	owner := C.webkit_responsible_pid(C.pid_t(pid))
	if owner <= 1 || uint32(owner) == pid {
		return path
	}
	ownerPath, err := getExecPathFromPID(uint32(owner))
	if err == nil && strings.Contains(ownerPath, ".app/Contents/MacOS/") {
		return ownerPath
	}
	return path
}

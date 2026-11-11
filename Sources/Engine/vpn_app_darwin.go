package dialer

/*
#cgo LDFLAGS: -framework CoreFoundation -framework SystemConfiguration
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <net/if.h>
#include <stdlib.h>

static unsigned int interfaceForService(CFStringRef id) {
	SCNetworkConnectionRef connection = SCNetworkConnectionCreateWithServiceID(NULL, id, NULL, NULL);
	if (!connection) return 0;
	CFDictionaryRef status = NULL;
	if (SCNetworkConnectionGetStatus(connection) == kSCNetworkConnectionConnected) {
		status = SCNetworkConnectionCopyExtendedStatus(connection);
	}
	CFRelease(connection);
	if (!status) return 0;

	const CFStringRef groups[] = {CFSTR("IPv4"), CFSTR("IPv6"), CFSTR("VPN")};
	unsigned int index = 0;
	for (int i = 0; i < 3 && index == 0; i++) {
		CFDictionaryRef group = CFDictionaryGetValue(status, groups[i]);
		if (!group || CFGetTypeID(group) != CFDictionaryGetTypeID()) continue;
		CFStringRef name = CFDictionaryGetValue(group, CFSTR("InterfaceName"));
		char interface[IF_NAMESIZE];
		if (name && CFGetTypeID(name) == CFStringGetTypeID() &&
		    CFStringGetCString(name, interface, sizeof(interface), kCFStringEncodingUTF8)) {
			index = if_nametoindex(interface);
		}
	}
	CFRelease(status);
	return index;
}

static int splitWebVPNInterface(const char *providers) {
	CFStringRef names = CFStringCreateWithCString(NULL, providers, kCFStringEncodingUTF8);
	if (!names) return 0;
	CFArrayRef allowed = CFStringCreateArrayBySeparatingStrings(NULL, names, CFSTR("|"));
	CFRelease(names);
	if (!allowed) return 0;

	SCPreferencesRef preferences = SCPreferencesCreate(NULL, CFSTR("SplitWebOnMac"), NULL);
	CFArrayRef services = preferences ? SCNetworkServiceCopyAll(preferences) : NULL;
	int index = 0;
	for (CFIndex i = 0; services && i < CFArrayGetCount(services); i++) {
		SCNetworkServiceRef service = CFArrayGetValueAtIndex(services, i);
		SCNetworkInterfaceRef interface = SCNetworkServiceGetInterface(service);
		CFDictionaryRef config = interface ? SCNetworkInterfaceGetConfiguration(interface) : NULL;
		CFStringRef provider = config ? CFDictionaryGetValue(config, CFSTR("NEProviderBundleIdentifier")) : NULL;
		CFStringRef id = SCNetworkServiceGetServiceID(service);
		if (!provider || CFGetTypeID(provider) != CFStringGetTypeID() || !id ||
		    !CFArrayContainsValue(allowed, CFRangeMake(0, CFArrayGetCount(allowed)), provider)) continue;
		int active = (int)interfaceForService(id);
		if (active == 0) continue;
		if (index != 0 && index != active) {
			index = -1;
			break;
		}
		index = active;
	}
	if (services) CFRelease(services);
	if (preferences) CFRelease(preferences);
	CFRelease(allowed);
	return index;
}
*/
import "C"

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func splitWebBindInterface(finder control.InterfaceFinder, name string) control.Func {
	providers, isVPN := strings.CutPrefix(name, "splitweb-vpn:")
	if !isVPN {
		return control.BindToInterface(finder, name, -1)
	}
	return func(network, _ string, conn syscall.RawConn) error {
		if providers == "" {
			return errors.New("VPN app is not connected")
		}
		names := C.CString(providers)
		index := int(C.splitWebVPNInterface(names))
		C.free(unsafe.Pointer(names))
		if index < 0 {
			return errors.New("VPN app has more than one active connection")
		} else if index == 0 {
			return errors.New("VPN app is not connected")
		}
		return control.Raw(conn, func(fd uintptr) error {
			if strings.HasSuffix(network, "6") {
				return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			}
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
		})
	}
}

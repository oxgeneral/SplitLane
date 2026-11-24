package dialer

/*
#cgo LDFLAGS: -framework CoreFoundation -framework SystemConfiguration
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <net/if.h>
#include <stdbool.h>
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

static int splitLaneVPNInterface(const char *target, bool service) {
	CFStringRef names = CFStringCreateWithCString(NULL, target, kCFStringEncodingUTF8);
	if (!names) return 0;
	if (service) {
		int index = (int)interfaceForService(names);
		CFRelease(names);
		return index;
	}
	CFArrayRef allowed = CFStringCreateArrayBySeparatingStrings(NULL, names, CFSTR("|"));
	CFRelease(names);
	if (!allowed) return 0;

	SCPreferencesRef preferences = SCPreferencesCreate(NULL, CFSTR("SplitLane"), NULL);
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
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

type vpnResolveKey struct {
	target  string
	service bool
}

type vpnResolveEntry struct {
	index     int
	expiresAt time.Time
}

const vpnResolveCacheTTL = 250 * time.Millisecond

type vpnResolver struct {
	mu    sync.Mutex
	cache map[vpnResolveKey]vpnResolveEntry
	now   func() time.Time
	query func(string, bool) int
}

var defaultVPNResolver = newVPNResolver(querySplitLaneVPNInterface, time.Now)

func newVPNResolver(query func(string, bool) int, now func() time.Time) *vpnResolver {
	return &vpnResolver{
		cache: make(map[vpnResolveKey]vpnResolveEntry),
		now:   now,
		query: query,
	}
}

func (r *vpnResolver) resolve(target string, service bool) int {
	if strings.IndexByte(target, 0) >= 0 {
		return 0
	}
	// SystemConfiguration APIs (SCPreferences / SCNetworkConnection) are not thread-safe;
	// serialize all lookups and briefly coalesce bursts of parallel dials.
	r.mu.Lock()
	defer r.mu.Unlock()

	key := vpnResolveKey{target: target, service: service}
	ts := r.now()
	if entry, ok := r.cache[key]; ok && ts.Before(entry.expiresAt) {
		return entry.index
	}
	index := r.query(target, service)
	if index > 0 {
		r.cache[key] = vpnResolveEntry{
			index:     index,
			expiresAt: ts.Add(vpnResolveCacheTTL),
		}
	} else {
		delete(r.cache, key)
	}
	return index
}

func splitLaneBindInterface(finder control.InterfaceFinder, name string) control.Func {
	if serviceID, ok := strings.CutPrefix(name, "splitlane-vpn-service:"); ok {
		return splitLaneVPNControl(serviceID, true, resolveSplitLaneVPN)
	}
	if providers, ok := strings.CutPrefix(name, "splitlane-vpn:"); ok {
		return splitLaneVPNControl(providers, false, resolveSplitLaneVPN)
	}
	return control.BindToInterface(finder, name, -1)
}

func resolveSplitLaneVPN(target string, service bool) int {
	return defaultVPNResolver.resolve(target, service)
}

func querySplitLaneVPNInterface(target string, service bool) int {
	name := C.CString(target)
	defer C.free(unsafe.Pointer(name))
	return int(C.splitLaneVPNInterface(name, C.bool(service)))
}

func splitLaneVPNControl(target string, service bool, resolve func(string, bool) int) control.Func {
	return func(network, _ string, conn syscall.RawConn) error {
		index := 0
		if target != "" {
			index = resolve(target, service)
		}
		if index < 0 {
			return errors.New("VPN app has more than one active connection")
		} else if index == 0 {
			if service {
				return errors.New("VPN profile is not connected")
			}
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

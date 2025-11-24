package utils

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type RootCollection struct {
	Collection        *ebpf.Collection
	RoleMap           *ebpf.Map
	MasterMap         *ebpf.Map
	AgentMap          *ebpf.Map
	EventsMap         *ebpf.Map
	RootProg          *ebpf.Program
	MasterCollections map[string]*ebpf.Collection // program name -> collection
}

func LoadRootCollection() (*RootCollection, error) {
	if _, err := os.Stat(RootObjPath); err != nil {
		return nil, fmt.Errorf("root object not found at %s: %w", RootObjPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(RootObjPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	// // Set pin path for maps that have pinning enabled
	// for _, mapSpec := range spec.Maps {
	// 	if mapSpec.Pinning != ebpf.PinNone {
	// 		mapSpec.Pinning = ebpf.PinByName
	// 	}
	// }
for name, mapSpec := range spec.Maps {
    switch name {
    case RoleMapName, MasterMapName, AgentMapName, EventsMapName:
        mapSpec.Pinning = ebpf.PinByName
    default:
        mapSpec.Pinning = ebpf.PinNone
    }
}
opts := ebpf.CollectionOptions{
    Maps: ebpf.MapOptions{
        PinPath: "/sys/fs/bpf/packetxpress",
    },
}
coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	rc := &RootCollection{
		Collection:        coll,
		MasterCollections: make(map[string]*ebpf.Collection),
	}

	// Now you can directly use maps from collection since they're auto-pinned
	rc.RoleMap = coll.Maps[RoleMapName]
	rc.MasterMap = coll.Maps[MasterMapName]
	rc.AgentMap = coll.Maps[AgentMapName]
	rc.EventsMap = coll.Maps[EventsMapName]

	if p, ok := coll.Programs[XdpRootProgName]; ok {
		rc.RootProg = p
	} else {
		for _, p := range coll.Programs {
			rc.RootProg = p
			break
		}
	}

	if rc.RoleMap == nil || rc.MasterMap == nil || rc.RootProg == nil {
		return rc, errors.New("failed to find expected maps or root program in collection")
	}
	return rc, nil
}

// LoadOrPinMap tries to load a map from pinned path, otherwise gets it from collection and pins it
func LoadOrPinMap(coll *ebpf.Collection, primaryName, fallbackName, pinPath string) *ebpf.Map {
	// Try to load from pinned path first
	if pinnedMap, err := ebpf.LoadPinnedMap(pinPath, nil); err == nil {
		fmt.Printf("Loaded pinned map from %s\n", pinPath)
		return pinnedMap
	}

	// If not pinned, get from collection
	var m *ebpf.Map
	if m2, ok := coll.Maps[primaryName]; ok {
		m = m2
	} else if m2, ok := coll.Maps[fallbackName]; ok {
		m = m2
	} else {
		return nil
	}

	// Pin the map
	if err := PinMap(m, pinPath); err != nil {
		log.Printf("Warning: Failed to pin map %s: %v", pinPath, err)
		return m // Return map anyway, even if pinning failed
	}

	return m
}

func DetachXDP(iface string) error {
	cmd := exec.Command("ip", "link", "set", "dev", iface, "xdp", "off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("detach xdp failed: %v - %s", err, string(out))
	}
	return nil
}

func AttachXDP(prog *ebpf.Program, iface string) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("program is nil")
	}
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("iface lookup: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceObj.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("attach xdp: %w", err)
	}
	return l, nil
}

func EnsureMasterObjs() error {
	for i := 0; i < NumMasters; i++ {
		path := MasterObjFiles[i]
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("missing master object %s", path)
		}
	}
	return nil
}

// PinMap pins a map to the filesystem if it's not already pinned
func PinMap(m *ebpf.Map, path string) error {
	if m == nil {
		return fmt.Errorf("map is nil")
	}

	// Check if already pinned
	if _, err := os.Stat(path); err == nil {
		// Try to load it to verify it's accessible
		if testMap, err := ebpf.LoadPinnedMap(path, nil); err == nil {
			testMap.Close() // Close the test handle
			fmt.Printf("Map already pinned at %s\n", path)
			return nil // Map is already pinned, no error
		}
		// If load failed, remove old pin and re-pin
		fmt.Printf("Removing stale pin at %s\n", path)
		os.Remove(path)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create pin directory %s: %w", dir, err)
	}

	// Pin the map
	if err := m.Pin(path); err != nil {
		return fmt.Errorf("pin map to %s: %w", path, err)
	}
	fmt.Printf("Pinned map to %s\n", path)
	return nil
}

// GetInterfaceIndex returns the interface index for a given interface name
func GetInterfaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("if lookup: %v", err)
	}
	return iface.Index
}

package utils

// import (
// 	"fmt"
// 	"log"
// 	"net"
// 	"os"

// 	"github.com/cilium/ebpf"
// 	"github.com/cilium/ebpf/link"
// )

// // // RootCollection holds the root eBPF collection and its maps
// // type RootCollection struct {
// // 	Collection *ebpf.Collection
// // 	RoleMap    *ebpf.Map
// // 	MasterMap  *ebpf.Map
// // 	AgentMap   *ebpf.Map
// // 	RootProg   *ebpf.Program
// // }

// // // LoadRootCollection loads the root eBPF program and its maps
// // func LoadRootCollection() (*RootCollection, error) {
// // 	rootObj, err := ebpf.LoadCollectionSpec(XdpRootObj)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("load spec: %w", err)
// // 	}

// // 	rootColl, err := ebpf.NewCollection(rootObj)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("create collection: %w", err)
// // 	}

// // 	roleMap := rootColl.Maps[RoleArrayMapName]
// // 	masterMap := rootColl.Maps[MasterArrayMapName]
// // 	agentMap := rootColl.Maps[AgentArrayMapName]

// // 	// Pin maps if not pinned
// // 	PinMap(roleMap, RoleArrayPinPath)
// // 	PinMap(masterMap, MasterArrayPinPath)
// // 	PinMap(agentMap, AgentArrayPinPath)

// // 	rootProg := rootColl.Programs[XdpRootProgramName]
// // 	if rootProg == nil {
// // 		rootColl.Close()
// // 		return nil, fmt.Errorf("root program not found")
// // 	}

// // 	return &RootCollection{
// // 		Collection: rootColl,
// // 		RoleMap:    roleMap,
// // 		MasterMap:  masterMap,
// // 		AgentMap:   agentMap,
// // 		RootProg:   rootProg,
// // 	}, nil
// // }


// // // AttachXDP attaches the root XDP program to the specified interface
// // func AttachXDP(rootProg *ebpf.Program, iface string) (link.Link, error) {
// // 	xdpLink, err := link.AttachXDP(link.XDPOptions{
// // 		Program:   rootProg,
// // 		Interface: GetInterfaceIndex(iface),
// // 		Flags:     link.XDPGenericMode,
// // 	})
// // 	if err != nil {
// // 		return nil, fmt.Errorf("attach XDP: %w", err)
// // 	}
// // 	return xdpLink, nil
// // }


package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"packetXpress/core"
	"packetXpress/utils"
	"syscall"

	"github.com/cilium/ebpf"
)

func main() {
	// Parse command-line arguments
	config := core.ParseFlags()
	
	if config.FirewallMode {
		
		    rootColl, err := utils.LoadRootCollection()
    if err != nil {
        log.Fatalf("Failed to load root collection: %v", err)
    }
    defer rootColl.Collection.Close()
		if err := core.UpdateFirewallPort(rootColl, config.Action, config.Dport); err != nil {
			log.Fatalf("Firewall error: %v", err)
		}

    fmt.Println("Firewall rule updated (XDP is already running)")
    return
	}
	// Load root eBPF collection
	rootColl, err := utils.LoadRootCollection()
	if err != nil {
		log.Fatalf("Failed to load root collection: %v", err)
	}
	defer rootColl.Collection.Close()

	// Setup role-specific configuration
	switch config.Role {
	case "master":
		if err := core.SetupMaster(rootColl); err != nil {
			log.Fatalf("Failed to setup master: %v", err)
		}
	case "agent":
		if err := core.SetupAgent(rootColl); err != nil {
			log.Fatalf("Failed to setup agent: %v", err)
		}
	default:
		log.Fatalf("Unknown role: %s", config.Role)
	}

	// Cleanup: close all master collections on exit
	defer func() {
		for progName, coll := range rootColl.MasterCollections {
			if coll != nil {
				coll.Close()
				fmt.Printf("Closed collection for %s\n", progName)
			}
		}
	}()

	// Detach any existing XDP program from interface first
	if err := utils.DetachXDP(config.Iface); err != nil {
		log.Printf("Warning: Failed to detach existing XDP program (may not exist): %v", err)
		// Continue anyway - interface might not have XDP attached
	}

	// Attach root XDP program to interface
	xdpLink, err := utils.AttachXDP(rootColl.RootProg, config.Iface)
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer xdpLink.Close()

	fmt.Println("XDP Root loaded and chain initialized")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get events map from packet profiler collection
	var eventsMap *ebpf.Map
	profilerProgName := utils.MasterProgramNames[2] // "xdp_packet_profiler"
	if profilerColl, ok := rootColl.MasterCollections[profilerProgName]; ok {
		if em, ok := profilerColl.Maps["events"]; ok {
			eventsMap = em
			log.Printf("Found events map in packet profiler collection")
		} else {
			log.Println("events map not found in packet profiler collection")
		}
	} else {
		log.Println("packet profiler collection not found")
	}

	if eventsMap != nil {
		if err := core.StartProfiler(ctx, eventsMap, utils.PROFILER_OUTPUT_FILE); err != nil {
			log.Fatalf("StartProfiler: %v", err)
		}
	} else {
		log.Println("packet profiler disabled: events map not available")
	}

	// Cleanup on exit: detach XDP
	defer func() {
		if err := utils.DetachXDP(config.Iface); err != nil {
			log.Printf("Warning: Failed to detach XDP on exit: %v", err)
		} else {
			log.Printf("Detached XDP from %s", config.Iface)
		}
	}()

	// wait for signal
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	cancel()
}

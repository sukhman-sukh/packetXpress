// gwdemo — userspace L4 reverse proxy demo (same routing logic as this module's Gateway).
//
//	go run ./cmd/gwdemo -config gwdemo.example.json
//
// See DEMO.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"packetxpress-sim"
)

type configFile struct {
	Listen   string `json:"listen"`
	Services []struct {
		Hostname string `json:"hostname"`
		Backends []struct {
			ID      string `json:"id"`
			Address string `json:"address"`
		} `json:"backends"`
	} `json:"services"`
}

func main() {
	configPath := flag.String("config", "", "path to JSON config (see gwdemo.example.json)")
	flag.Parse()

	if *configPath == "" {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "\nExample: go run ./cmd/gwdemo -config gwdemo.example.json\n")
		os.Exit(2)
	}

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}

	var cfg configFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}

	for i, svc := range cfg.Services {
		if svc.Hostname == "" {
			log.Fatalf("services[%d]: hostname is required", i)
		}
		if len(svc.Backends) == 0 {
			log.Fatalf("services[%d]: at least one backend is required", i)
		}
		for j, b := range svc.Backends {
			if b.ID == "" || b.Address == "" {
				log.Fatalf("services[%d].backends[%d]: id and address are required", i, j)
			}
		}
	}

	gw, err := sim.NewGateway(cfg.Listen)
	if err != nil {
		log.Fatalf("gateway listen %q: %v", cfg.Listen, err)
	}

	for _, svc := range cfg.Services {
		backends := make([]sim.BackendInfo, 0, len(svc.Backends))
		for _, b := range svc.Backends {
			backends = append(backends, sim.BackendInfo{ID: b.ID, Address: b.Address})
		}
		gw.AddService(svc.Hostname, backends)
		log.Printf("registered service hostname=%q backends=%d", svc.Hostname, len(backends))
	}

	go gw.Serve()

	log.Printf("gateway listening on %s (HTTP Host or TLS SNI selects service)", gw.Addr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = gw.Close()
	log.Println("shutdown complete")
}

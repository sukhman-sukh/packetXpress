/*
 * balancer.go — userspace control plane for the XDP L4 reverse proxy
 *
 * Responsibilities:
 *   1. Load pxp_balancer.o and register it in master_array[1].
 *   2. Populate rp_backends BPF map from LbConfig.
 *   3. On config change: rebuild Maglev tables, install new conntrack entries.
 *   4. Run the AF_XDP slow-path router (new-flow SNI/Host parsing → CT install).
 */
package core

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"packetXpress/utils"

	"github.com/cilium/ebpf"
)

/* ── Config persistence ──────────────────────────────────────── */

func loadLbConfig() (*utils.LbConfig, error) {
	cfg := &utils.LbConfig{}
	data, err := os.ReadFile(utils.LbConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read lb config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse lb config: %w", err)
	}
	return cfg, nil
}

func saveLbConfig(cfg *utils.LbConfig) error {
	dir := filepath.Dir(utils.LbConfigFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(utils.LbConfigFile, data, 0644)
}

/* ── BPF map helpers ─────────────────────────────────────────── */

// backendsMapFromCollection returns rp_backends from an in-process rootColl (daemon path).
func backendsMapFromCollection(rootColl *utils.RootCollection) (*ebpf.Map, error) {
	if rootColl == nil {
		return nil, fmt.Errorf("root collection is nil")
	}
	coll, ok := rootColl.MasterCollections["pxp_balancer"]
	if !ok {
		return nil, fmt.Errorf("balancer collection not loaded")
	}
	m, ok := coll.Maps[utils.RpBackendsMapName]
	if !ok {
		return nil, fmt.Errorf("map %s not found in balancer collection", utils.RpBackendsMapName)
	}
	return m, nil
}

// acquireBackendsMapForSync returns rp_backends: from rootColl when set, otherwise from
// the pinned map (standalone `xpx lb` after the master has loaded once).
// closeFn must always be called when err == nil (no-op when map is owned by rootColl).
func acquireBackendsMapForSync(rootColl *utils.RootCollection) (m *ebpf.Map, closeFn func(), err error) {
	if rootColl != nil {
		if m, err = backendsMapFromCollection(rootColl); err == nil {
			return m, func() {}, nil
		}
	}
	m, err = ebpf.LoadPinnedMap(utils.RpBackendsPinPath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("load pinned %s: %w", utils.RpBackendsPinPath, err)
	}
	return m, func() { m.Close() }, nil
}

// ipToNetBytes converts a dotted-decimal IP string to a 4-byte array
// in network byte order.
func ipToNetBytes(ipStr string) ([4]byte, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return [4]byte{}, fmt.Errorf("invalid IPv4: %s", ipStr)
	}
	var b [4]byte
	copy(b[:], ip)
	return b, nil
}

// macToBytes parses a colon-separated MAC string.
func macToBytes(macStr string) ([6]byte, error) {
	hw, err := net.ParseMAC(macStr)
	if err != nil {
		return [6]byte{}, err
	}
	var b [6]byte
	copy(b[:], hw)
	return b, nil
}

/* ── LbAddService / LbRemoveService / LbSync ─────────────────── */

// LbAddService adds a service to the configuration and syncs to BPF maps.
func LbAddService(rootColl *utils.RootCollection, svc utils.ServiceCfg) error {
	cfg, err := loadLbConfig()
	if err != nil {
		return err
	}
	// Replace if hostname already exists.
	replaced := false
	for i, s := range cfg.Services {
		if s.Hostname == svc.Hostname {
			cfg.Services[i] = svc
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.Services = append(cfg.Services, svc)
	}
	if err := saveLbConfig(cfg); err != nil {
		return err
	}
	return lbSyncBPF(rootColl, cfg)
}

// LbRemoveService removes a service by hostname.
func LbRemoveService(rootColl *utils.RootCollection, hostname string) error {
	cfg, err := loadLbConfig()
	if err != nil {
		return err
	}
	filtered := cfg.Services[:0]
	for _, s := range cfg.Services {
		if s.Hostname != hostname {
			filtered = append(filtered, s)
		}
	}
	cfg.Services = filtered
	if err := saveLbConfig(cfg); err != nil {
		return err
	}
	return lbSyncBPF(rootColl, cfg)
}

// LbSync forces a re-sync of BPF maps from stored configuration.
func LbSync(rootColl *utils.RootCollection) error {
	cfg, err := loadLbConfig()
	if err != nil {
		return err
	}
	return lbSyncBPF(rootColl, cfg)
}

// LbListServices prints the current configuration.
func LbListServices() error {
	cfg, err := loadLbConfig()
	if err != nil {
		return err
	}
	if len(cfg.Services) == 0 {
		fmt.Println("No services configured.")
		return nil
	}
	for _, svc := range cfg.Services {
		fmt.Printf("Service: %s (hostname=%s)\n", svc.Name, svc.Hostname)
		for _, b := range svc.Backends {
			fmt.Printf("  backend id=%-10s ip=%-15s mac=%s ifindex=%d\n",
				b.ID, b.IP, b.MAC, b.Ifindex)
		}
	}
	return nil
}

// lbSyncBPF rebuilds the rp_backends BPF map from the config.
// Backends from all services are merged into a single flat array
// (backend_idx 0..N), keyed by a global monotonically-assigned index.
func lbSyncBPF(rootColl *utils.RootCollection, cfg *utils.LbConfig) error {
	bm, closeBm, err := acquireBackendsMapForSync(rootColl)
	if err != nil {
		log.Printf("warn: cannot sync BPF backends map: %v", err)
		return nil
	}
	defer closeBm()

	idx := uint32(0)
	for _, svc := range cfg.Services {
		for _, b := range svc.Backends {
			ip, err := ipToNetBytes(b.IP)
			if err != nil {
				return fmt.Errorf("service %s backend %s: %w", svc.Name, b.ID, err)
			}
			mac, err := macToBytes(b.MAC)
			if err != nil {
				return fmt.Errorf("service %s backend %s MAC: %w", svc.Name, b.ID, err)
			}

			be := utils.RpBackend{
				Ifindex: uint32(b.Ifindex),
			}
			// Store real_ip in network byte order.
			binary.BigEndian.PutUint32(be.RealIP[:], binary.BigEndian.Uint32(ip[:]))
			be.RealMAC = mac

			if err := bm.Put(idx, be); err != nil {
				return fmt.Errorf("put backend %d: %w", idx, err)
			}
			idx++
		}
	}
	// Remove stale backend slots so old indices are not used after shrink.
	for i := idx; i < uint32(utils.RpMaxBackends); i++ {
		_ = bm.Delete(i)
	}
	fmt.Printf("Synced %d backends to BPF map.\n", idx)
	return nil
}

/* ── Slow-path router (AF_XDP) ──────────────────────────────── */

// RouterConfig holds per-hostname routing tables for the slow-path daemon.
type RouterConfig struct {
	// hostname → list of backend entries (for Maglev)
	Services map[string][]routerBackend
	// hostname → MaglevTable
	Maglev map[string]*utils.MaglevTable
}

type routerBackend struct {
	Idx  uint32
	Info utils.BackendCfg
}

// BuildRouterConfig builds an in-memory routing config from LbConfig.
func BuildRouterConfig(cfg *utils.LbConfig) *RouterConfig {
	rc := &RouterConfig{
		Services: make(map[string][]routerBackend),
		Maglev:   make(map[string]*utils.MaglevTable),
	}
	globalIdx := uint32(0)
	for _, svc := range cfg.Services {
		backends := make([]routerBackend, len(svc.Backends))
		names := make([]string, len(svc.Backends))
		for i, b := range svc.Backends {
			backends[i] = routerBackend{Idx: globalIdx, Info: b}
			names[i] = b.ID
			globalIdx++
		}
		rc.Services[svc.Hostname] = backends
		rc.Maglev[svc.Hostname] = utils.BuildMaglev(names, 0)
	}
	return rc
}

// InstallConntrack installs a conntrack entry in the rp_flow_ct BPF map.
// Called by the slow-path router after SNI/Host parsing.
func InstallConntrack(rootColl *utils.RootCollection, fk utils.RpFlowKey, backendIdx uint32) error {
	var ctMap *ebpf.Map
	var closeFn func()

	if rootColl != nil {
		if coll, ok := rootColl.MasterCollections["pxp_balancer"]; ok {
			if m, ok := coll.Maps[utils.RpFlowCtMapName]; ok {
				ctMap = m
				closeFn = func() {}
			}
		}
	}
	if ctMap == nil {
		m, err := ebpf.LoadPinnedMap(utils.RpFlowCtPinPath, nil)
		if err != nil {
			return fmt.Errorf("flow ct map: %w", err)
		}
		ctMap = m
		closeFn = func() { m.Close() }
	}
	defer closeFn()

	val := utils.RpCtVal{
		BackendIdx: backendIdx,
		LastSeenNs: uint64(time.Now().UnixNano()),
	}
	return ctMap.Put(fk, val)
}

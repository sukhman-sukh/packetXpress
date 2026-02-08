/*
 * firewalling.go — LBVS-based firewall rule management
 *
 * Implements the userspace control plane for the XDP firewall:
 *   - Rule storage (JSON file)
 *   - LBVS bitvector computation
 *   - BPF map synchronization
 *
 * When a rule is added/removed, ALL bitvectors are recomputed from
 * scratch and pushed to the pinned BPF maps.  This matches the paper's
 * approach (Section 5, "Ruleset changes").
 */
package core

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"packetXpress/utils"

	"github.com/cilium/ebpf"
)

/* ================================================================
 * Rule persistence — JSON file on disk
 * ================================================================ */

func loadFwConfig() (*utils.FwConfig, error) {
	cfg := &utils.FwConfig{
		Rules:    []utils.FwRule{},
		Policies: map[string]string{"INPUT": "accept", "FORWARD": "accept"},
		LocalIPs: []string{},
	}

	data, err := os.ReadFile(utils.FwRulesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read rules file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse rules file: %w", err)
	}
	// Ensure policies map is never nil
	if cfg.Policies == nil {
		cfg.Policies = map[string]string{"INPUT": "accept", "FORWARD": "accept"}
	}
	return cfg, nil
}

func saveFwConfig(cfg *utils.FwConfig) error {
	dir := filepath.Dir(utils.FwRulesFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(utils.FwRulesFile, data, 0644)
}

/* ================================================================
 * Conversion helpers
 * ================================================================ */

// ipToUint32 converts an IP string to uint32 in network byte order.
// Returns 0 for empty/"0.0.0.0" (wildcard).
func ipToUint32(ipStr string) uint32 {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "*" {
		return 0
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIP(v uint32) string {
	if v == 0 {
		return "*"
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip.String()
}

func actionStringToUint(action string) uint32 {
	switch strings.ToLower(action) {
	case "drop":
		return utils.FwActionDrop
	case "accept":
		return utils.FwActionAccept
	case "forward":
		return utils.FwActionForward
	default:
		return utils.FwActionAccept
	}
}

func actionUintToString(a uint32) string {
	switch a {
	case utils.FwActionDrop:
		return "DROP"
	case utils.FwActionAccept:
		return "ACCEPT"
	case utils.FwActionForward:
		return "FORWARD"
	default:
		return "ACCEPT"
	}
}

func protoToString(p uint32) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 0:
		return "*"
	default:
		return fmt.Sprintf("%d", p)
	}
}

/* ================================================================
 * LBVS bitvector computation
 *
 * For each of the 5 match fields, we build:
 *   - A hash map: field_value → bitvector (with wildcard bits merged in)
 *   - A wildcard bitvector (fallback for unknown values)
 *
 * Plus chain masks, actions, and forward params.
 * ================================================================ */

type lbvsData struct {
	srcIPBV   map[uint32]uint64
	dstIPBV   map[uint32]uint64
	srcPortBV map[uint32]uint64
	dstPortBV map[uint32]uint64
	protoBV   map[uint32]uint64

	wildcardBV [5]uint64 // indexed by FW_FIELD_*

	actions   []uint32 // per-rule action
	chainMask [2]uint64 // 0=INPUT, 1=FORWARD
	fwdParams map[uint32]utils.FwFwdParams
}

func computeLBVS(rules []utils.FwRule) *lbvsData {
	data := &lbvsData{
		srcIPBV:   make(map[uint32]uint64),
		dstIPBV:   make(map[uint32]uint64),
		srcPortBV: make(map[uint32]uint64),
		dstPortBV: make(map[uint32]uint64),
		protoBV:   make(map[uint32]uint64),
		actions:   make([]uint32, len(rules)),
		fwdParams: make(map[uint32]utils.FwFwdParams),
	}

	for i, rule := range rules {
		if i >= utils.FwMaxRules {
			fmt.Printf("Warning: rule %d exceeds max %d, skipping\n", i, utils.FwMaxRules)
			break
		}
		bit := uint64(1) << uint(i)

		// ---- Chain mask ----
		switch strings.ToUpper(rule.Chain) {
		case "INPUT":
			data.chainMask[utils.FwChainInput] |= bit
		case "FORWARD":
			data.chainMask[utils.FwChainForward] |= bit
		}

		// ---- Action ----
		data.actions[i] = actionStringToUint(rule.Action)

		// ---- Forward params ----
		if strings.ToLower(rule.Action) == "forward" {
			fwd := utils.FwFwdParams{}
			if rule.FwdIface != "" {
				iface, err := net.InterfaceByName(rule.FwdIface)
				if err == nil {
					fwd.Ifindex = uint32(iface.Index)
					if len(iface.HardwareAddr) >= 6 {
						copy(fwd.SrcMAC[:], iface.HardwareAddr[:6])
					}
				} else {
					fmt.Printf("Warning: interface %s not found: %v\n", rule.FwdIface, err)
				}
			}
			if rule.FwdDstMAC != "" {
				mac, err := net.ParseMAC(rule.FwdDstMAC)
				if err == nil && len(mac) >= 6 {
					copy(fwd.DstMAC[:], mac[:6])
				}
			}
			if rule.FwdSrcMAC != "" {
				mac, err := net.ParseMAC(rule.FwdSrcMAC)
				if err == nil && len(mac) >= 6 {
					copy(fwd.SrcMAC[:], mac[:6])
				}
			}
			data.fwdParams[uint32(i)] = fwd
		}

		// ---- Source IP ----
		srcIP := ipToUint32(rule.SrcIP)
		if srcIP == 0 {
			data.wildcardBV[0] |= bit // wildcard
		} else {
			data.srcIPBV[srcIP] |= bit
		}

		// ---- Destination IP ----
		dstIP := ipToUint32(rule.DstIP)
		if dstIP == 0 {
			data.wildcardBV[1] |= bit
		} else {
			data.dstIPBV[dstIP] |= bit
		}

		// ---- Source Port ----
		if rule.SrcPort == 0 {
			data.wildcardBV[2] |= bit
		} else {
			data.srcPortBV[rule.SrcPort] |= bit
		}

		// ---- Destination Port ----
		if rule.DstPort == 0 {
			data.wildcardBV[3] |= bit
		} else {
			data.dstPortBV[rule.DstPort] |= bit
		}

		// ---- Protocol ----
		if rule.Protocol == 0 {
			data.wildcardBV[4] |= bit
		} else {
			data.protoBV[rule.Protocol] |= bit
		}
	}

	/*
	 * Merge wildcard bits into every value-specific bitvector.
	 * This is the key LBVS insight: if rule i has wildcard for field F,
	 * then rule i's bit must appear in EVERY entry of field F's hash map,
	 * because any packet value for F satisfies a wildcard.
	 */
	for v := range data.srcIPBV {
		data.srcIPBV[v] |= data.wildcardBV[0]
	}
	for v := range data.dstIPBV {
		data.dstIPBV[v] |= data.wildcardBV[1]
	}
	for v := range data.srcPortBV {
		data.srcPortBV[v] |= data.wildcardBV[2]
	}
	for v := range data.dstPortBV {
		data.dstPortBV[v] |= data.wildcardBV[3]
	}
	for v := range data.protoBV {
		data.protoBV[v] |= data.wildcardBV[4]
	}

	return data
}

/* ================================================================
 * BPF map operations
 * ================================================================ */

func openPinnedMap(name string) (*ebpf.Map, error) {
	path := filepath.Join(utils.FwPinPath, name)
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("map '%s' not found at %s (is packetXpress running?): %w",
			name, path, err)
	}
	return m, nil
}

// clearBVHashMap clears a hash map with uint32 keys and uint64 values.
func clearBVHashMap(m *ebpf.Map) {
	var key uint32
	var val uint64
	iter := m.Iterate()
	var keys []uint32
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		_ = m.Delete(k)
	}
}

// clearU8HashMap clears a hash map with uint32 keys and uint8 values.
func clearU8HashMap(m *ebpf.Map) {
	var key uint32
	var val uint8
	iter := m.Iterate()
	var keys []uint32
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		_ = m.Delete(k)
	}
}

// clearFwdHashMap clears the forward params hash map.
func clearFwdHashMap(m *ebpf.Map) {
	var key uint32
	var val utils.FwFwdParams
	iter := m.Iterate()
	var keys []uint32
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		_ = m.Delete(k)
	}
}

/* ================================================================
 * syncMaps — push LBVS data into all BPF maps
 * ================================================================ */

func syncMaps(data *lbvsData, policies map[string]string, localIPs []string) error {
	// ---- Open all pinned maps ----
	type namedMap struct {
		name string
		m    *ebpf.Map
	}
	mapNames := []string{
		utils.FwMapSrcIPBV, utils.FwMapDstIPBV,
		utils.FwMapSrcPortBV, utils.FwMapDstPortBV,
		utils.FwMapProtoBV, utils.FwMapWildcardBV,
		utils.FwMapActions, utils.FwMapChainMask,
		utils.FwMapDefaultAction, utils.FwMapLocalIPs,
		utils.FwMapFwdParams,
	}

	maps := make(map[string]*ebpf.Map, len(mapNames))
	for _, name := range mapNames {
		m, err := openPinnedMap(name)
		if err != nil {
			// Close already-opened maps
			for _, om := range maps {
				om.Close()
			}
			return err
		}
		maps[name] = m
	}
	defer func() {
		for _, m := range maps {
			m.Close()
		}
	}()

	// ---- Clear hash maps ----
	clearBVHashMap(maps[utils.FwMapSrcIPBV])
	clearBVHashMap(maps[utils.FwMapDstIPBV])
	clearBVHashMap(maps[utils.FwMapSrcPortBV])
	clearBVHashMap(maps[utils.FwMapDstPortBV])
	clearBVHashMap(maps[utils.FwMapProtoBV])
	clearU8HashMap(maps[utils.FwMapLocalIPs])
	clearFwdHashMap(maps[utils.FwMapFwdParams])

	// ---- Populate bitvector hash maps ----
	for k, v := range data.srcIPBV {
		if err := maps[utils.FwMapSrcIPBV].Put(k, v); err != nil {
			return fmt.Errorf("put src_ip_bv: %w", err)
		}
	}
	for k, v := range data.dstIPBV {
		if err := maps[utils.FwMapDstIPBV].Put(k, v); err != nil {
			return fmt.Errorf("put dst_ip_bv: %w", err)
		}
	}
	for k, v := range data.srcPortBV {
		if err := maps[utils.FwMapSrcPortBV].Put(k, v); err != nil {
			return fmt.Errorf("put src_port_bv: %w", err)
		}
	}
	for k, v := range data.dstPortBV {
		if err := maps[utils.FwMapDstPortBV].Put(k, v); err != nil {
			return fmt.Errorf("put dst_port_bv: %w", err)
		}
	}
	for k, v := range data.protoBV {
		if err := maps[utils.FwMapProtoBV].Put(k, v); err != nil {
			return fmt.Errorf("put proto_bv: %w", err)
		}
	}

	// ---- Wildcard bitvectors (array, 5 entries) ----
	for i := uint32(0); i < 5; i++ {
		if err := maps[utils.FwMapWildcardBV].Put(i, data.wildcardBV[i]); err != nil {
			return fmt.Errorf("put wildcard_bv[%d]: %w", i, err)
		}
	}

	// ---- Per-rule actions (array) ----
	for i := uint32(0); i < uint32(len(data.actions)); i++ {
		if err := maps[utils.FwMapActions].Put(i, data.actions[i]); err != nil {
			return fmt.Errorf("put actions[%d]: %w", i, err)
		}
	}
	// Zero out remaining slots
	for i := uint32(len(data.actions)); i < utils.FwMaxRules; i++ {
		_ = maps[utils.FwMapActions].Put(i, uint32(0))
	}

	// ---- Chain masks (array, 2 entries) ----
	if err := maps[utils.FwMapChainMask].Put(uint32(0), data.chainMask[0]); err != nil {
		return fmt.Errorf("put chain_mask[0]: %w", err)
	}
	if err := maps[utils.FwMapChainMask].Put(uint32(1), data.chainMask[1]); err != nil {
		return fmt.Errorf("put chain_mask[1]: %w", err)
	}

	// ---- Default actions per chain ----
	for chain, action := range policies {
		var idx uint32
		switch strings.ToUpper(chain) {
		case "INPUT":
			idx = 0
		case "FORWARD":
			idx = 1
		default:
			continue
		}
		if err := maps[utils.FwMapDefaultAction].Put(idx, actionStringToUint(action)); err != nil {
			return fmt.Errorf("put default_action[%d]: %w", idx, err)
		}
	}

	// ---- Local IPs ----
	val := uint8(1)
	for _, ipStr := range localIPs {
		ip := ipToUint32(ipStr)
		if ip != 0 {
			if err := maps[utils.FwMapLocalIPs].Put(ip, val); err != nil {
				return fmt.Errorf("put local_ips[%s]: %w", ipStr, err)
			}
		}
	}

	// ---- Forward params ----
	for k, v := range data.fwdParams {
		if err := maps[utils.FwMapFwdParams].Put(k, v); err != nil {
			return fmt.Errorf("put fwd_params[%d]: %w", k, err)
		}
	}

	return nil
}

/* ================================================================
 * Public API — called by CLI handlers
 * ================================================================ */

// FwAddRule appends a rule, recomputes LBVS, and syncs maps.
func FwAddRule(rule utils.FwRule) error {
	cfg, err := loadFwConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if len(cfg.Rules) >= utils.FwMaxRules {
		return fmt.Errorf("maximum %d rules reached", utils.FwMaxRules)
	}

	rule.ID = len(cfg.Rules)
	cfg.Rules = append(cfg.Rules, rule)

	data := computeLBVS(cfg.Rules)
	if err := syncMaps(data, cfg.Policies, cfg.LocalIPs); err != nil {
		return fmt.Errorf("sync maps: %w", err)
	}

	if err := saveFwConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Rule %d added: chain=%s action=%s\n", rule.ID, rule.Chain, rule.Action)
	return nil
}

// FwDelRule removes a rule by ID, recomputes LBVS, and syncs maps.
func FwDelRule(id int) error {
	cfg, err := loadFwConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if id < 0 || id >= len(cfg.Rules) {
		return fmt.Errorf("rule ID %d out of range [0..%d)", id, len(cfg.Rules))
	}

	cfg.Rules = append(cfg.Rules[:id], cfg.Rules[id+1:]...)
	// Re-index
	for i := range cfg.Rules {
		cfg.Rules[i].ID = i
	}

	data := computeLBVS(cfg.Rules)
	if err := syncMaps(data, cfg.Policies, cfg.LocalIPs); err != nil {
		return fmt.Errorf("sync maps: %w", err)
	}

	if err := saveFwConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Rule %d deleted, %d rules remaining\n", id, len(cfg.Rules))
	return nil
}

// FwListRules prints all rules and policies.
func FwListRules() error {
	cfg, err := loadFwConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Println("=== Firewall Configuration ===")
	fmt.Printf("Default Policies: INPUT=%s  FORWARD=%s\n",
		strings.ToUpper(cfg.Policies["INPUT"]),
		strings.ToUpper(cfg.Policies["FORWARD"]))
	fmt.Printf("Local IPs: %v\n", cfg.LocalIPs)
	fmt.Println()

	if len(cfg.Rules) == 0 {
		fmt.Println("No rules configured.")
		return nil
	}

	fmt.Printf("%-4s %-8s %-16s %-16s %-7s %-7s %-6s %-8s %-10s\n",
		"ID", "Chain", "SrcIP", "DstIP", "SPort", "DPort", "Proto", "Action", "FwdIface")
	fmt.Println(strings.Repeat("-", 82))

	for _, r := range cfg.Rules {
		srcIP := r.SrcIP
		if srcIP == "" {
			srcIP = "*"
		}
		dstIP := r.DstIP
		if dstIP == "" {
			dstIP = "*"
		}
		sp := "*"
		if r.SrcPort != 0 {
			sp = fmt.Sprintf("%d", r.SrcPort)
		}
		dp := "*"
		if r.DstPort != 0 {
			dp = fmt.Sprintf("%d", r.DstPort)
		}
		proto := protoToString(r.Protocol)
		fwdIf := "-"
		if r.FwdIface != "" {
			fwdIf = r.FwdIface
		}

		fmt.Printf("%-4d %-8s %-16s %-16s %-7s %-7s %-6s %-8s %-10s\n",
			r.ID, r.Chain, srcIP, dstIP, sp, dp, proto,
			strings.ToUpper(r.Action), fwdIf)
	}

	return nil
}

// FwSetPolicy sets the default policy for a chain and syncs maps.
func FwSetPolicy(chain, action string) error {
	chain = strings.ToUpper(chain)
	if chain != "INPUT" && chain != "FORWARD" {
		return fmt.Errorf("invalid chain: %s (must be INPUT or FORWARD)", chain)
	}

	cfg, err := loadFwConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	cfg.Policies[chain] = strings.ToLower(action)

	data := computeLBVS(cfg.Rules)
	if err := syncMaps(data, cfg.Policies, cfg.LocalIPs); err != nil {
		return fmt.Errorf("sync maps: %w", err)
	}

	if err := saveFwConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Default policy for %s set to %s\n", chain, strings.ToUpper(action))
	return nil
}

// FwAddLocalIP adds a local IP for chain selection and syncs maps.
func FwAddLocalIP(ipStr string) error {
	cfg, err := loadFwConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Validate
	if net.ParseIP(ipStr) == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	// Check for duplicates
	for _, existing := range cfg.LocalIPs {
		if existing == ipStr {
			fmt.Printf("Local IP %s already exists\n", ipStr)
			return nil
		}
	}

	cfg.LocalIPs = append(cfg.LocalIPs, ipStr)

	data := computeLBVS(cfg.Rules)
	if err := syncMaps(data, cfg.Policies, cfg.LocalIPs); err != nil {
		return fmt.Errorf("sync maps: %w", err)
	}

	if err := saveFwConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Local IP %s added\n", ipStr)
	return nil
}

// FwDelLocalIP removes a local IP and syncs maps.
func FwDelLocalIP(ipStr string) error {
	cfg, err := loadFwConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	found := false
	newIPs := make([]string, 0, len(cfg.LocalIPs))
	for _, ip := range cfg.LocalIPs {
		if ip == ipStr {
			found = true
			continue
		}
		newIPs = append(newIPs, ip)
	}
	if !found {
		return fmt.Errorf("local IP %s not found", ipStr)
	}
	cfg.LocalIPs = newIPs

	data := computeLBVS(cfg.Rules)
	if err := syncMaps(data, cfg.Policies, cfg.LocalIPs); err != nil {
		return fmt.Errorf("sync maps: %w", err)
	}

	if err := saveFwConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Local IP %s removed\n", ipStr)
	return nil
}

// FwSync recomputes LBVS from stored rules and syncs all maps.
// Called on startup or manually to ensure BPF state matches stored config.
func FwSync() error {
	cfg, err := loadFwConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	data := computeLBVS(cfg.Rules)
	if err := syncMaps(data, cfg.Policies, cfg.LocalIPs); err != nil {
		return err
	}

	fmt.Printf("Firewall synced: %d rules, policies INPUT=%s FORWARD=%s, %d local IPs\n",
		len(cfg.Rules),
		strings.ToUpper(cfg.Policies["INPUT"]),
		strings.ToUpper(cfg.Policies["FORWARD"]),
		len(cfg.LocalIPs))
	return nil
}

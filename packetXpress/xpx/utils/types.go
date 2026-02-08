package utils

// Config holds the parsed command-line configuration
type Config struct {
	Role  string
	Iface string

	FirewallMode bool
	FwArgs       []string
}


type FwRule struct {
	ID       int    `json:"id"`
	Chain    string `json:"chain"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint32 `json:"src_port"`
	DstPort  uint32 `json:"dst_port"`
	Protocol uint32 `json:"protocol"`
	Action   string `json:"action"`

	// Forward-specific params (only when action = "forward")
	FwdIface  string `json:"fwd_iface,omitempty"`
	FwdDstMAC string `json:"fwd_dst_mac,omitempty"`
	FwdSrcMAC string `json:"fwd_src_mac,omitempty"`
}

// FwConfig stores the full firewall configuration (persisted as JSON)
type FwConfig struct {
	Rules    []FwRule          `json:"rules"`
	Policies map[string]string `json:"policies"` // chain → "drop"|"accept"
	LocalIPs []string          `json:"local_ips"`
}

// FwFwdParams matches the BPF struct fw_fwd_params (16 bytes, packed)
type FwFwdParams struct {
	Ifindex uint32
	SrcMAC  [6]byte
	DstMAC  [6]byte
}

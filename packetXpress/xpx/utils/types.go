package utils

// Config holds the parsed command-line configuration
type Config struct {
	Role  string
	Iface string

	// Firewall mode
	FirewallMode bool
	Action       string
	Dport        int
}

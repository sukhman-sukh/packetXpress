package utils

// Config holds the parsed command-line configuration
type Config struct {
	Role  string // "master" or "agent"
	Iface string // Network interface name
}

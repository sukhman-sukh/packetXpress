package utils

const (

	// Map names
	RoleArrayMapName   = "role_array"
	MasterArrayMapName = "master_array"
	AgentArrayMapName  = "agent_array"

	// Map pin paths
	RoleArrayPinPath   = "/sys/fs/bpf/role_array"
	MasterArrayPinPath = "/sys/fs/bpf/master_array"
	AgentArrayPinPath  = "/sys/fs/bpf/agent_array"

	// Program names
	XdpRootProgramName = "xdp_root"

	// Roles (must match bpf/pxp_constants.h: ROLE_MODE_MASTER=0, ROLE_MODE_AGENT=1)
	ROLE_MASTER = 0 // matches ROLE_MODE_MASTER in BPF
	ROLE_AGENT  = 1 // matches ROLE_MODE_AGENT in BPF
	ROLE_KEY    = 0

	// Number of Masters (for loop upper bound in main.go)
	NumMasters = 4

	RootObjPath     = "../build/xdp_root.o"
	XdpRootProgName = "xdp_root"
	EventsMapName   = "events"
	RoleMapName     = "role_array"
	MasterMapName   = "master_array"
	AgentMapName    = "agent_array"

	PROFILER_OUTPUT_FILE = "/tmp/packetXpress/packet_profiler.log"
)

// Master program names (from BPF files: SEC names)
// Order: firewall -> balancer -> packet_profiler -> forwarder
var MasterProgramNames = [NumMasters]string{
	"pxp_firewall",        // from pxp_firewall.c
	"pxp_balancer",        // from pxp_balancer.c
	"pxp_packet_profiler", // from pxp_packetprofiler.c
	"pxp_forwarder",       // from pxp_forwarder.c
}

// Master object file paths (from build directory)
// Order: firewall -> balancer -> packet_profiler -> forwarder
var MasterObjFiles = [NumMasters]string{
	"../build/pxp_firewall.o",       // from pxp_firewall.c
	"../build/pxp_balancer.o",       // from pxp_balancer.c
	"../build/pxp_packetprofiler.o", // from pxp_packetprofiler.c
	"../build/pxp_forwarder.o",      // from pxp_forwarder.c
}

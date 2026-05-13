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

	// Roles
	ROLE_MASTER = 0
	ROLE_AGENT  = 1
	ROLE_KEY    = 0

	// Master pipeline
	NumMasters = 4

	RootObjPath     = "../build/xdp_root.o"
	XdpRootProgName = "xdp_root"
	EventsMapName   = "events"
	RoleMapName     = "role_array"
	MasterMapName   = "master_array"
	AgentMapName    = "agent_array"

	PROFILER_OUTPUT_FILE = "/tmp/packetXpress/packet_profiler.log"

	// Firewall BPF map names
	FwMapSrcIPBV       = "fw_src_ip_bv"
	FwMapDstIPBV       = "fw_dst_ip_bv"
	FwMapSrcPortBV     = "fw_src_port_bv"
	FwMapDstPortBV     = "fw_dst_port_bv"
	FwMapProtoBV       = "fw_proto_bv"
	FwMapWildcardBV    = "fw_wildcard_bv"
	FwMapActions       = "fw_actions"
	FwMapChainMask     = "fw_chain_mask"
	FwMapDefaultAction = "fw_default_action"
	FwMapLocalIPs      = "fw_local_ips"
	FwMapFwdParams     = "fw_fwd_params_map"

	// Firewall pin path
	FwPinPath   = "/sys/fs/bpf/packetxpress"
	FwRulesFile = "/tmp/packetxpress/firewall_rules.json"

	// Firewall constants (must match BPF defines)
	FwMaxRules      = 64
	FwActionDrop    = 0
	FwActionAccept  = 1
	FwActionForward = 2
	FwChainInput    = 0
	FwChainForward  = 1

	// ── Reverse-proxy BPF map names ──────────────────────────────────────────
	RpFlowCtMapName   = "rp_flow_ct"
	RpBackendsMapName = "rp_backends"
	RpSlowpathMapName = "rp_slowpath"

	// ── Reverse-proxy pin paths ───────────────────────────────────────────────
	RpFlowCtPinPath   = "/sys/fs/bpf/packetxpress/rp_flow_ct"
	RpBackendsPinPath = "/sys/fs/bpf/packetxpress/rp_backends"
	RpSlowpathPinPath = "/sys/fs/bpf/packetxpress/rp_slowpath"

	// RpMaxBackends must match BPF RP_MAX_BACKENDS in pxp_constants.h
	RpMaxBackends = 256

	// ── Reverse-proxy config file ─────────────────────────────────────────────
	LbConfigFile = "/tmp/packetxpress/lb_config.json"

	// ── Maglev table size (must be prime) ─────────────────────────────────────
	MaglevTableSize = 65537
)

// Master program SEC names — order: firewall → balancer → profiler → forwarder
var MasterProgramNames = [NumMasters]string{
	"pxp_firewall",
	"pxp_balancer",
	"pxp_packet_profiler",
	"pxp_forwarder",
}

// Master object file paths (from build directory)
var MasterObjFiles = [NumMasters]string{
	"../build/pxp_firewall.o",
	"../build/pxp_balancer.o",
	"../build/pxp_packetprofiler.o",
	"../build/pxp_forwarder.o",
}

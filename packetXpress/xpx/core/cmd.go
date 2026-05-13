package core

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"packetXpress/utils"
)

// ParseFlags handles the top-level CLI.
// Detects "fw" / "lb" subcommands first, otherwise parses normal XDP flags.
func ParseFlags() *utils.Config {
	// ---- Detect "fw" subcommand ----
	if len(os.Args) > 1 && os.Args[1] == "fw" {
		return &utils.Config{
			FirewallMode: true,
			FwArgs:       os.Args[2:],
		}
	}

	// ---- Detect "lb" subcommand ----
	if len(os.Args) > 1 && os.Args[1] == "lb" {
		return &utils.Config{
			BalancerMode: true,
			BalancerArgs: os.Args[2:],
		}
	}

	// ---- Normal XDP mode ----
	roleFlag := flag.String("role", "", "Role: master or agent")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage:\n"+
				"  %s --role <master|agent> <iface>      Start XDP pipeline\n"+
				"  %s fw <subcommand> [flags]             Firewall management\n\n"+
				"Firewall subcommands:\n"+
				"  add       Add a firewall rule\n"+
				"  del       Delete a rule by ID\n"+
				"  list      List all rules and policies\n"+
				"  policy    Set default policy for a chain\n"+
				"  local-ip  Manage local IPs for chain selection\n"+
				"  sync      Force re-sync BPF maps from stored rules\n\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *roleFlag != "master" && *roleFlag != "agent" {
		fmt.Fprintln(os.Stderr, "Must specify --role master|agent, or use 'fw' subcommand")
		flag.Usage()
		os.Exit(1)
	}
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Missing interface name")
		flag.Usage()
		os.Exit(1)
	}

	return &utils.Config{
		Role:  *roleFlag,
		Iface: flag.Arg(0),
	}
}

// HandleFirewallCommand dispatches firewall subcommands.
func HandleFirewallCommand(args []string) {
	if len(args) == 0 {
		fwUsage()
		os.Exit(1)
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "add":
		handleFwAdd(subArgs)
	case "del":
		handleFwDel(subArgs)
	case "list", "ls":
		handleFwList()
	case "policy":
		handleFwPolicy(subArgs)
	case "local-ip":
		handleFwLocalIP(subArgs)
	case "sync":
		handleFwSync()
	default:
		fmt.Fprintf(os.Stderr, "Unknown firewall subcommand: %s\n", subcmd)
		fwUsage()
		os.Exit(1)
	}
}

func fwUsage() {
	fmt.Fprintf(os.Stderr, `Firewall subcommands:

  add --chain <INPUT|FORWARD> [--src-ip IP] [--dst-ip IP]
      [--src-port PORT] [--dst-port PORT] [--proto tcp|udp|icmp|NUM]
      --action <drop|accept|forward>
      [--fwd-if IFACE] [--fwd-dst-mac MAC] [--fwd-src-mac MAC]

  del --id <RULE_ID>

  list

  policy --chain <INPUT|FORWARD> --action <drop|accept>

  local-ip --add <IP>
  local-ip --del <IP>

  sync

`)
}

/* ---- fw add ---- */

func handleFwAdd(args []string) {
	fs := flag.NewFlagSet("fw add", flag.ExitOnError)
	chain := fs.String("chain", "", "Chain: INPUT or FORWARD (required)")
	srcIP := fs.String("src-ip", "", "Source IP (empty = any)")
	dstIP := fs.String("dst-ip", "", "Destination IP (empty = any)")
	srcPort := fs.Int("src-port", 0, "Source port (0 = any)")
	dstPort := fs.Int("dst-port", 0, "Destination port (0 = any)")
	proto := fs.String("proto", "", "Protocol: tcp, udp, icmp, or number (empty = any)")
	action := fs.String("action", "", "Action: drop, accept, forward (required)")
	fwdIf := fs.String("fwd-if", "", "Forward: output interface name")
	fwdDstMAC := fs.String("fwd-dst-mac", "", "Forward: destination MAC (next-hop)")
	fwdSrcMAC := fs.String("fwd-src-mac", "", "Forward: source MAC (our interface)")

	fs.Parse(args)

	if *chain == "" || *action == "" {
		fmt.Fprintln(os.Stderr, "--chain and --action are required")
		fs.Usage()
		os.Exit(1)
	}

	chainUpper := strings.ToUpper(*chain)
	if chainUpper != "INPUT" && chainUpper != "FORWARD" {
		fmt.Fprintln(os.Stderr, "--chain must be INPUT or FORWARD")
		os.Exit(1)
	}

	actionLower := strings.ToLower(*action)
	if actionLower != "drop" && actionLower != "accept" && actionLower != "forward" {
		fmt.Fprintln(os.Stderr, "--action must be drop, accept, or forward")
		os.Exit(1)
	}

	rule := utils.FwRule{
		Chain:     chainUpper,
		SrcIP:     *srcIP,
		DstIP:     *dstIP,
		SrcPort:   uint32(*srcPort),
		DstPort:   uint32(*dstPort),
		Protocol:  parseProto(*proto),
		Action:    actionLower,
		FwdIface:  *fwdIf,
		FwdDstMAC: *fwdDstMAC,
		FwdSrcMAC: *fwdSrcMAC,
	}

	if err := FwAddRule(rule); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

/* ---- fw del ---- */

func handleFwDel(args []string) {
	fs := flag.NewFlagSet("fw del", flag.ExitOnError)
	id := fs.Int("id", -1, "Rule ID to delete (required)")
	fs.Parse(args)

	if *id < 0 {
		fmt.Fprintln(os.Stderr, "--id is required")
		os.Exit(1)
	}

	if err := FwDelRule(*id); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

/* ---- fw list ---- */

func handleFwList() {
	if err := FwListRules(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

/* ---- fw policy ---- */

func handleFwPolicy(args []string) {
	fs := flag.NewFlagSet("fw policy", flag.ExitOnError)
	chain := fs.String("chain", "", "Chain: INPUT or FORWARD (required)")
	action := fs.String("action", "", "Default action: drop or accept (required)")
	fs.Parse(args)

	if *chain == "" || *action == "" {
		fmt.Fprintln(os.Stderr, "--chain and --action are required")
		os.Exit(1)
	}

	if err := FwSetPolicy(*chain, *action); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

/* ---- fw local-ip ---- */

func handleFwLocalIP(args []string) {
	fs := flag.NewFlagSet("fw local-ip", flag.ExitOnError)
	addIP := fs.String("add", "", "Add a local IP")
	delIP := fs.String("del", "", "Remove a local IP")
	fs.Parse(args)

	if *addIP != "" {
		if err := FwAddLocalIP(*addIP); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if *delIP != "" {
		if err := FwDelLocalIP(*delIP); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Specify --add <IP> or --del <IP>")
		os.Exit(1)
	}
}

/* ---- fw sync ---- */

func handleFwSync() {
	if err := FwSync(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

/* ---- helpers ---- */

/* ══════════════════════════════════════════════════════════════
 * lb — L4 reverse-proxy management subcommands
 * ══════════════════════════════════════════════════════════════ */

// HandleBalancerCommand dispatches "lb" subcommands.
func HandleBalancerCommand(args []string) {
	if len(args) == 0 {
		lbUsage()
		os.Exit(1)
	}
	subcmd := args[0]
	subArgs := args[1:]
	switch subcmd {
	case "add-service":
		handleLbAddService(subArgs)
	case "del-service":
		handleLbDelService(subArgs)
	case "list", "ls":
		handleLbList()
	case "sync":
		handleLbSync()
	default:
		fmt.Fprintf(os.Stderr, "Unknown lb subcommand: %s\n", subcmd)
		lbUsage()
		os.Exit(1)
	}
}

func lbUsage() {
	fmt.Fprint(os.Stderr, `Load-balancer subcommands:

  add-service --hostname <sni-or-host> [--name <name>]
              --backends <id:ip:mac:ifindex>[,...]

  del-service --hostname <sni-or-host>

  list

  sync

`)
}

func handleLbAddService(args []string) {
	fs := flag.NewFlagSet("lb add-service", flag.ExitOnError)
	hostname := fs.String("hostname", "", "SNI / HTTP Host value (required)")
	name := fs.String("name", "", "Human-readable service name (defaults to hostname)")
	backendsStr := fs.String("backends", "", "Comma-separated id:ip:mac:ifindex triples (required)")
	fs.Parse(args)

	if *hostname == "" || *backendsStr == "" {
		fmt.Fprintln(os.Stderr, "--hostname and --backends are required")
		fs.Usage()
		os.Exit(1)
	}
	if *name == "" {
		*name = *hostname
	}

	var backends []utils.BackendCfg
	for _, part := range strings.Split(*backendsStr, ",") {
		fields := strings.Split(strings.TrimSpace(part), ":")
		if len(fields) < 4 {
			fmt.Fprintf(os.Stderr, "invalid backend %q — format: id:ip:mac:ifindex\n", part)
			os.Exit(1)
		}
		ifIdx, err := strconv.Atoi(fields[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid ifindex in %q: %v\n", part, err)
			os.Exit(1)
		}
		backends = append(backends, utils.BackendCfg{
			ID:      fields[0],
			IP:      fields[1],
			MAC:     fields[2],
			Ifindex: ifIdx,
		})
	}

	svc := utils.ServiceCfg{
		Name:     *name,
		Hostname: *hostname,
		Backends: backends,
	}

	if err := LbAddService(nil, svc); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Service %q added with %d backend(s).\n", *hostname, len(backends))
}

func handleLbDelService(args []string) {
	fs := flag.NewFlagSet("lb del-service", flag.ExitOnError)
	hostname := fs.String("hostname", "", "SNI / HTTP Host (required)")
	fs.Parse(args)
	if *hostname == "" {
		fmt.Fprintln(os.Stderr, "--hostname required")
		os.Exit(1)
	}
	if err := LbRemoveService(nil, *hostname); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Service %q removed.\n", *hostname)
}

func handleLbList() {
	if err := LbListServices(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func handleLbSync() {
	if err := LbSync(nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

/* ---- helpers ---- */

func parseProto(s string) uint32 {
	switch strings.ToLower(s) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "", "any", "*":
		return 0
	default:
		n, err := strconv.Atoi(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid protocol: %s\n", s)
			os.Exit(1)
		}
		return uint32(n)
	}
}

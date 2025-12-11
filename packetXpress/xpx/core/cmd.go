package core

import (
	"flag"
	"fmt"
	"os"

	"packetXpress/utils"
)

func ParseFlags() *utils.Config {
	roleFlag := flag.String("role", "", "Role of this node: master or agent (required unless --fw is used)")
	fwFlag := flag.Bool("fw", false, "Enable firewall mode")
	actionFlag := flag.String("action", "", "Firewall action: drop or accept (required when --fw)")
	dportFlag := flag.Int("dport", 0, "Destination port for firewall rule (required when --fw)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s --role <master|agent> <iface>\n   or: %s --fw --action <drop|accept> --dport <port>\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// FIREWALL MODE
	if *fwFlag {
		if *actionFlag != "drop" && *actionFlag != "accept" {
			fmt.Fprintln(os.Stderr, "--fw requires --action drop|accept")
			os.Exit(1)
		}
		if *dportFlag <= 0 {
			fmt.Fprintln(os.Stderr, "--fw requires --dport <port>")
			os.Exit(1)
		}
		return &utils.Config{
			FirewallMode: true,
			Action:       *actionFlag,
			Dport:        *dportFlag,
		}
	}

	// NORMAL XDP MODE
	if *roleFlag != "master" && *roleFlag != "agent" {
		fmt.Fprintln(os.Stderr, "Must specify --role unless --fw is used")
		flag.Usage()
		os.Exit(1)
	}
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	return &utils.Config{
		Role:  *roleFlag,
		Iface: flag.Arg(0),
	}
}

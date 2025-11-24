package core

import (
	"flag"
	"fmt"
	"os"

	"packetXpress/utils"
)

// ParseFlags parses command-line arguments and returns a Config
// Exits the program if arguments are invalid
func ParseFlags() *utils.Config {
	roleFlag := flag.String("role", "", "Role of this node: master or agent (required)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s --role <master|agent> <iface>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *roleFlag != "master" && *roleFlag != "agent" {
		fmt.Fprintf(os.Stderr, "Must specify --role as either 'master' or 'agent'\n")
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

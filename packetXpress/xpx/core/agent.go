package core

import (
	"fmt"

	"packetXpress/utils"
	// "github.com/cilium/ebpf"
)

func SetupAgent(rootColl *utils.RootCollection) error {
	// you can implement the agent module loader like master; minimal stub here
	roleValue := uint32(utils.ROLE_AGENT)
	if err := rootColl.RoleMap.Put(uint32(utils.ROLE_KEY), roleValue); err != nil {
		return fmt.Errorf("put role: %w", err)
	}
	fmt.Println("Role set to AGENT (no modules loaded by default)")
	return nil
}

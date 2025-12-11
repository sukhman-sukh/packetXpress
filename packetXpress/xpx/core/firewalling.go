package core

import (
    "fmt"
    "packetXpress/utils"
    "github.com/cilium/ebpf"
)

func UpdateFirewallPort(rootColl *utils.RootCollection, action string, dport int) error {
    fwMap, ok := rootColl.Collection.Maps["firewall_dport"]
    if !ok {
        return fmt.Errorf("firewall_dport map not found")
    }

    key := uint32(0)
    var value uint16

    switch action {
    case "drop":
        value = uint16(dport)
    case "accept":
        value = 0 // disable drop rule
    default:
        return fmt.Errorf("invalid action: %s (expected drop|accept)", action)
    }

    if err := fwMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
        return fmt.Errorf("failed to update firewall_dport map: %v", err)
    }

    fmt.Printf("[XDP FIREWALL] %s %d\n", action, dport)
    return nil
}

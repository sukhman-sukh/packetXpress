package core

import (
	"fmt"
	"path/filepath"

	"packetXpress/utils"

	"github.com/cilium/ebpf"
)

func SetupMaster(rootColl *utils.RootCollection) error {
	// ensure master objects exist
	if err := utils.EnsureMasterObjs(); err != nil {
		return fmt.Errorf("ensure master objs: %w", err)
	}

	// set role -> MASTER
	roleValue := uint32(utils.ROLE_MASTER)
	if err := rootColl.RoleMap.Put(uint32(utils.ROLE_KEY), roleValue); err != nil {
		return fmt.Errorf("put role: %w", err)
	}

	// load and populate master program FDs
	for i := 0; i < utils.NumMasters; i++ {
		file := utils.MasterObjFiles[i]
		spec, err := ebpf.LoadCollectionSpec(file)
		if err != nil {
			return fmt.Errorf("load spec %s: %w", file, err)
		}
		// 	for _, mapSpec := range spec.Maps {
		// 	mapSpec.Pinning = ebpf.PinNone
		// }
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
    Maps: ebpf.MapOptions{
        PinPath: "/sys/fs/bpf/packetxpress",
    },
})
		if err != nil {
			return fmt.Errorf("new collection %s: %w", file, err)
		}

		// get program name from constants array (matches SEC name in BPF file)
		progName := utils.MasterProgramNames[i]
		prog, ok := coll.Programs[progName]
		if !ok || prog == nil {
			coll.Close()
			return fmt.Errorf("program %s not found in %s", progName, file)
		}

		// Store collection in map for later access to maps/programs
		rootColl.MasterCollections[progName] = coll

		fd := prog.FD()
		if fd < 0 {
			coll.Close()
			return fmt.Errorf("invalid program FD for %s: %d", progName, fd)
		}
		fmt.Printf("populate %d", fd)
		// if err := rootColl.MasterMap.Put(uint32(i), fd); err != nil {
		// 	coll.Close()
		// 	return fmt.Errorf("populate master_array index %d: %w", i, err)
		// }
		if err := rootColl.MasterMap.Put(uint32(i), uint32(fd)); err != nil {
			coll.Close()
			return fmt.Errorf("populate master_array index %d: %w", i, err)
		}
		// Verify the FD was stored correctly
		// var storedFD uint32
		// if err := rootColl.MasterMap.Lookup(uint32(i), &storedFD); err != nil {
		// 	return fmt.Errorf("failed to verify stored FD at index %d: %w", i, err)
		// }
		// if storedFD != uint32(fd) {
		// 	return fmt.Errorf("FD mismatch: stored %d but expected %d", storedFD, fd)
		// }

		fmt.Printf("populated master_array[%d] with FD=%d (program=%s from %s)\n",
			i, fd, progName, filepath.Base(file))
	}

	return nil
}

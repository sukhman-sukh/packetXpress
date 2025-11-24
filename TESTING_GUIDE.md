# Packet Profiler Testing Guide

## Overview

The packet profiler captures IPv4 packet metadata (5-tuple, TTL, TCP flags, etc.) and writes it to a log file. It runs as the 3rd master program in the chain.

## Prerequisites

1. **Root access**: XDP requires root or CAP_BPF, CAP_NET_ADMIN capabilities
2. **BPF programs compiled**: All `.o` files in `build/` directory
3. **Go program built**: `packetXpress` binary in `xpx/` directory
4. **Network interface**: A real network interface (not all interfaces support XDP)

## Step-by-Step Testing

### Step 1: Build Everything

```bash
cd /home/Sukhi/Desktop/projects/packetXpress/packetXpress

# Build BPF programs
make clean
make bpfs

# Verify all object files exist
ls -lh build/*.o
# Should see: pxp_balancer.o, pxp_firewall.o, pxp_forwarder.o, pxp_packetprofiler.o, xdp_root.o

# Build Go program
cd xpx
go build -o packetXpress
```

### Step 2: Choose a Test Interface

**Option A: Use a real interface (recommended)**

```bash
# List available interfaces
ip link show

# Choose an interface that:
# - Has traffic (e.g., eth0, enp0s3, wlan0)
# - Supports XDP (most Ethernet interfaces do)
# Example: eth0
```

**Option B: Create a veth pair for testing**

```bash
# Create virtual Ethernet pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo ip addr add 192.168.100.1/24 dev veth0
sudo ip addr add 192.168.100.2/24 dev veth1

# Use veth0 for testing
```

### Step 3: Prepare Output Directory

```bash
# Create log directory (if needed)
mkdir -p /tmp/packetXpress

# Clear old logs (optional)
rm -f /tmp/packetXpress/packet_profiler.log
```

### Step 4: Run the Program

```bash
cd /home/Sukhi/Desktop/projects/packetXpress/packetXpress/xpx

# Run as root (required for XDP)
sudo ./packetXpress --role master <interface_name>

# Example:
sudo ./packetXpress --role master eth0
```

**Expected output:**

```
populated master_array[0] with FD=X (program=xdp_firewall from pxp_firewall.o)
populated master_array[1] with FD=X (program=xdp_balancer from pxp_balancer.o)
populated master_array[2] with FD=X (program=xdp_packet_profiler from pxp_packetprofiler.o)
populated master_array[3] with FD=X (program=xdp_forwarder from pxp_forwarder.o)
XDP Root loaded and chain initialized
Found events map in packet profiler collection
profiler: writing events to /tmp/packetXpress/packet_profiler.log
```

**If you see "packet profiler disabled"**, check:

- The packet profiler collection was loaded (should see it in the output above)
- The events map exists in the collection

### Step 5: Generate Test Traffic

**In another terminal**, generate traffic:

**A. ICMP (ping) - Simplest test:**

```bash
ping -c 10 8.8.8.8
# or ping your gateway
ping -c 10 $(ip route | grep default | awk '{print $3}')
```

**B. TCP traffic:**

```bash
# HTTP request
curl -v http://example.com

# Or use netcat
echo "test" | nc example.com 80
```

**C. UDP traffic:**

```bash
# DNS query
dig @8.8.8.8 example.com

# Or netcat UDP
echo "test" | nc -u 8.8.8.8 53
```

**D. High volume (for stress testing):**

```bash
# Generate many packets
for i in {1..100}; do ping -c 1 8.8.8.8 & done; wait
```

### Step 6: Monitor the Log File

**In a third terminal**, watch the log:

```bash
# Real-time monitoring
tail -f /tmp/packetXpress/packet_profiler.log

# Or check periodically
watch -n 1 'tail -20 /tmp/packetXpress/packet_profiler.log'

# Or just view it
cat /tmp/packetXpress/packet_profiler.log
```

**Expected log format:**

```
2024-11-23T12:34:56.789012345Z cpu=0 if=2 proto=1 flags=0x0 ttl=64 192.168.1.100:0 -> 8.8.8.8:0 icmp=8/0
2024-11-23T12:34:56.789123456Z cpu=1 if=2 proto=6 flags=0x2 ttl=64 192.168.1.100:54321 -> 93.184.216.34:80 icmp=0/0
2024-11-23T12:34:56.789234567Z cpu=0 if=2 proto=17 flags=0x0 ttl=64 192.168.1.100:12345 -> 8.8.8.8:53 icmp=0/0
```

**Field explanation:**

- `cpu`: CPU core that processed the packet
- `if`: Interface index
- `proto`: IP protocol (1=ICMP, 6=TCP, 17=UDP)
- `flags`: TCP flags (hex, only for TCP)
- `ttl`: Time to live
- `src:port -> dst:port`: Source and destination IP:port
- `icmp`: ICMP type/code (only for ICMP packets)

### Step 7: Verify BPF Program is Running

```bash
# Check XDP programs attached
sudo ip link show <interface>
# Look for "xdp" in the output

# List all BPF programs
sudo bpftool prog list | grep -E "xdp|packet"

# Check BPF maps
sudo bpftool map list | grep events

# View kernel logs (bpf_printk output)
sudo dmesg | tail -50 | grep pxp
# Should see: "pxp <src_ip>:<port> -> <dst_ip>:<port> proto=X cpu=X if=X"
```

### Step 8: Stop the Program

```bash
# In the terminal running packetXpress, press Ctrl+C
# Or send SIGTERM
sudo pkill -TERM packetXpress

# The program will:
# - Close the ring buffer reader
# - Close the log file
# - Detach XDP program
# - Close all collections
```

## Troubleshooting

### Issue: "packet profiler collection not found"

**Cause**: Master programs weren't loaded successfully

**Fix**:

1. Check that all BPF object files exist: `ls -lh build/*.o`
2. Verify the program names match: Check `MasterProgramNames` in `constants.go`
3. Check for errors in the SetupMaster output

### Issue: "events map not found in packet profiler collection"

**Cause**: The events map isn't in the packet profiler BPF program

**Fix**:

1. Verify `pxp_packetprofiler.c` has the events map defined
2. Recompile: `make clean && make bpfs`
3. Check the map name matches: Should be `"events"`

### Issue: No events in log file

**Possible causes**:

1. **No traffic on interface**:

   ```bash
   # Verify traffic
   sudo tcpdump -i <interface> -n -c 10
   ```

2. **Only IPv6 traffic** (profiler only handles IPv4):

   ```bash
   # Check for IPv4 packets
   sudo tcpdump -i <interface> ip -n -c 10
   ```

3. **Ring buffer full** (unlikely but possible):

   - Check kernel logs: `sudo dmesg | grep -i "ring\|bpf"`
   - Increase ring buffer size in `pxp_packetprofiler.c` if needed

4. **Program not in chain**:

   - Verify packet profiler is at index 2 in master_array
   - Check that root program tail-calls to master programs

5. **XDP not attached**:
   ```bash
   sudo ip link show <interface>
   # Should show "xdp" flag
   ```

### Issue: "Failed to attach XDP"

**Causes**:

- Interface doesn't support XDP
- Another XDP program already attached
- Insufficient permissions

**Fix**:

```bash
# Remove existing XDP program
sudo ip link set dev <interface> xdp off

# Try again
sudo ./packetXpress --role master <interface>
```

### Issue: Compilation errors

**BPF compilation**:

```bash
# Check clang version (needs 10+)
clang --version

# Try compiling manually
cd bpf
clang -I. -target bpf -O2 -c pxp_packetprofiler.c -o /tmp/test.o
```

**Go compilation**:

```bash
cd xpx
go mod tidy
go build -v
```

## Quick Test Script

Create `test_profiler.sh`:

```bash
#!/bin/bash
set -e

IFACE=${1:-eth0}
OUTPUT="/tmp/packetXpress/packet_profiler.log"

echo "=== Packet Profiler Test ==="
echo "Interface: $IFACE"
echo "Output: $OUTPUT"
echo ""

cd /home/Sukhi/Desktop/projects/packetXpress/packetXpress

echo "1. Building BPF programs..."
make clean && make bpfs

echo "2. Building Go program..."
cd xpx
go build -o packetXpress

echo "3. Cleaning old logs..."
rm -f "$OUTPUT"
mkdir -p "$(dirname "$OUTPUT")"

echo "4. Starting packetXpress..."
echo "   (Run this in background or another terminal)"
echo "   sudo ./packetXpress --role master $IFACE"
echo ""
echo "5. After starting, generate traffic:"
echo "   ping -c 5 8.8.8.8"
echo ""
echo "6. Check log file:"
echo "   tail -f $OUTPUT"
```

Make executable: `chmod +x test_profiler.sh`

## Advanced Testing

### Test with specific packet types

```bash
# Only TCP
sudo tcpdump -i <interface> tcp -w /tmp/tcp.pcap
# Then replay: sudo tcpreplay -i <interface> /tmp/tcp.pcap

# Only UDP
sudo tcpdump -i <interface> udp -w /tmp/udp.pcap

# Only ICMP
ping -c 10 8.8.8.8
```

### Performance testing

```bash
# Generate high packet rate
sudo pktgen -i <interface> -n 100000

# Monitor CPU usage
top -p $(pgrep packetXpress)

# Check ring buffer drops
sudo bpftool map dump name events
```

### Verify data accuracy

Compare profiler output with tcpdump:

```bash
# Run both simultaneously
sudo tcpdump -i <interface> -n > /tmp/tcpdump.log &
sudo ./packetXpress --role master <interface> &
ping -c 10 8.8.8.8
# Compare outputs
```

## Expected Results

After successful testing, you should see:

1. ✅ Program starts without errors
2. ✅ "Found events map" message appears
3. ✅ "profiler: writing events" message appears
4. ✅ Log file is created at `/tmp/packetXpress/packet_profiler.log`
5. ✅ Events appear in log when traffic is generated
6. ✅ Events contain correct IP addresses, ports, protocols
7. ✅ TCP flags are captured for TCP packets
8. ✅ ICMP type/code are captured for ICMP packets
9. ✅ Program cleans up properly on exit (Ctrl+C)

## Next Steps

Once basic testing works:

1. Test with different packet sizes
2. Test with fragmented packets
3. Test with high packet rates
4. Verify integration with other master programs (firewall, balancer)
5. Test error handling (ring buffer full, etc.)

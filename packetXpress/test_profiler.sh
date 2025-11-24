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
echo "   Run in another terminal:"
echo "   cd $(pwd) && sudo ./packetXpress --role master $IFACE"
echo ""
echo "5. After starting, generate traffic:"
echo "   ping -c 5 8.8.8.8"
echo ""
echo "6. Check log file:"
echo "   tail -f $OUTPUT"

#!/bin/bash

# --- Configuration Variables ---
HOST_IF="veth-host"
CLIENT_IF="veth-client"
CLIENT_NS="clientns"
HOST_IP="10.0.0.1/24"
CLIENT_IP="10.0.0.2/24"
CLIENT_GW="10.0.0.1"

# --- Clean Up Previous State ---
echo "Cleaning up previous state..."
ip netns del $CLIENT_NS 2>/dev/null
ip link del $HOST_IF 2>/dev/null
echo "Cleanup complete."

# --- Create veth pair on the host ---
echo "Creating VETH pair: $HOST_IF <--> $CLIENT_IF"
ip link add $HOST_IF type veth peer name $CLIENT_IF
if [ $? -ne 0 ]; then echo "Error: Failed to create VETH pair." && exit 1; fi

# --- Configure host side ($HOST_IF) ---
echo "Configuring Host Interface ($HOST_IF)"
ip link set $HOST_IF up
ip addr add $HOST_IP dev $HOST_IF

echo "Disabling checksum offload on $HOST_IF..."
ethtool -K $HOST_IF rx off tx off

# --- Create Client Network Namespace ---
echo "Creating client network namespace ($CLIENT_NS)"
ip netns add $CLIENT_NS

# --- Move $CLIENT_IF into the clientns ---
echo "Moving $CLIENT_IF into $CLIENT_NS"
ip link set $CLIENT_IF netns $CLIENT_NS

# --- Inside clientns: configure $CLIENT_IF ---
echo "Configuring Client Interface ($CLIENT_IF) inside $CLIENT_NS"
ip netns exec $CLIENT_NS ip link set $CLIENT_IF up
ip netns exec $CLIENT_NS ip link set dev $CLIENT_IF address 02:00:00:00:00:02
ip netns exec $CLIENT_NS ip addr add $CLIENT_IP dev $CLIENT_IF

# --- Inside clientns: bring up loopback and default route ---
echo "Finalizing clientns configuration"
ip netns exec $CLIENT_NS ip link set lo up
ip netns exec $CLIENT_NS ip route add default via $CLIENT_GW

# --- Sanity Checks ---
echo ""
echo "======================================================="
echo "               VETH SETUP SANITY CHECKS"
echo "======================================================="

echo ""
echo "CHECK 1: Host Interface Status"
ip addr show $HOST_IF

echo ""
echo "CHECK 2: Host Routing Table"
ip route | grep $HOST_IF

echo ""
echo "CHECK 3: Client Namespace Interface Status"
ip netns exec $CLIENT_NS ip addr

echo ""
echo "CHECK 4: Client Namespace Routing Table"
ip netns exec $CLIENT_NS ip route

echo ""
echo "CHECK 5: PING Test (Client -> Host)"
ip netns exec $CLIENT_NS ping -c1 $CLIENT_GW

echo "======================================================="
echo "Setup and checks complete. You can now use 'sudo ip netns exec $CLIENT_NS <command>'"
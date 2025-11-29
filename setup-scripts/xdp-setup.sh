#!/bin/bash
# Script to add a specific iptables rule to the OUTPUT chain.

# This rule prevents the local machine from sending TCP RST (Reset) packets
# for connections originating from source port 6379
# Prevents kernel from screwing up the xdp backend

sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 6379 -j DROP

# Check the exit status of the previous command
if [ $? -eq 0 ]; then
    echo "Rule successfully added to the OUTPUT chain."
else
    echo "Error: Failed to add the iptables rule. Check permissions or configuration."
fi
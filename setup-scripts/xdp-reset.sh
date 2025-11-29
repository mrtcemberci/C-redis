#!/bin/bash
# Script to delete a specific iptables rule from the OUTPUT chain.

# The rule blocks outbound TCP RST packets originating from port 6379

# Prevents kernel from dropping your XDP packets. sets it back to normal.
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 6379 -j DROP

# Check the exit status of the previous command
if [ $? -eq 0 ]; then
    echo "Rule successfully deleted from the OUTPUT chain."
else
    echo "Error: Failed to delete the iptables rule. (It might not exist or permissions are insufficient)."
fi
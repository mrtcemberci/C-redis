set -e #exit if any command fails


echo "--- Starting Server in Background ---"
# Redirects the server output to server.log for both stdout and stderr
# & means run in the background (do not wait for it)
./redis-clone > server.log 2>&1 &
SERVER_PID=$! # Get the Process ID of the last command

# trap ensures no matter how we exit server is dead
trap "echo '--- Shutting Down Server ---'; kill $SERVER_PID" EXIT

# Give the server a moment to start up
sleep 0.5

# Simulate client, redirecte input into the netcat and redirect the output to the .actual file
echo "--- Running Integration Test ---"
cat tests/basic_test.in | netcat -w 1 localhost 6379 > tests/basic_test.actual

echo "--- Comparing Results ---"
if diff -q tests/basic_test.expected tests/basic_test.actual; then
    echo "  PASSED: Output matches expected."
else
    echo "  FAILED: Output MISMATCH!"
    echo "--- EXPECTED ---"
    cat tests/basic_test.expected
    echo ""
    echo "--- ACTUAL ---"
    cat tests/basic_test.actual
    exit 1 
fi

# The 'trap' will now run and kill the server
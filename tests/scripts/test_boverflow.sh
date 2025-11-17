# This script runs the "buffer overflow" (DoS) test
# against the server.

set -e # Exit immediately if any command fails

echo "---  Starting Server in Background ---"
./redis-clone > server.log 2>&1 &
SERVER_PID=$!
trap "echo '--- Shutting Down Server ---'; kill $SERVER_PID" EXIT
sleep 0.5 # Give server time to boot

echo "---  Running DoS Attack Test ---"

# Define file paths
TEST_EXPECTED="tests/data/expected/boverflow.expected"
TEST_ACTUAL="tests/data/actual/boverflow.actual"

# This is the attack
# We pipe 2MB of 'A's (with no newline) into netcat.
python3 -c 'print("A" * 2000000, end="")' | netcat localhost 6379 > $TEST_ACTUAL

echo "---  Comparing Results ---"
if diff -q $TEST_EXPECTED $TEST_ACTUAL; then
    echo "  PASSED: Server correctly rejected the large command."
else
    echo "  FAILED: DoS test output MISMATCH!"
    echo "--- EXPECTED ---"
    cat $TEST_EXPECTED
    echo ""
    echo "--- ACTUAL ---"
    cat $TEST_ACTUAL
    exit 1 
fi

# Trap will run and kill the server
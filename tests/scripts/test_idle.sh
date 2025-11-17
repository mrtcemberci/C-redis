# This script tests the idle timeout functionality.
# It connects and waits to be disconnected.
#
# NOTE: This test requires IDLE_TIMEOUT_SECONDS in server.c
#       to be set to a low value (e.g., 3 seconds).

set -e # Exit immediately if any command fails

echo "---  Starting Server in Background ---"
./redis-clone > server.log 2>&1 &
SERVER_PID=$!
# Updated trap to use echo
trap "echo '--- Shutting Down Server ---'; kill $SERVER_PID" EXIT
sleep 0.5 # Give server time to boot (Fixed typo: was 'echo 0.5')

echo "---  Running Idle Timeout Test ---"

# Define file paths
TEST_EXPECTED="tests/data/expected/idle_test.expected"
TEST_ACTUAL="tests/data/actual/idle_test.actual"

# This is the "test".
# We pipe 'sleep 5' (which sends no data) into netcat.
# This keeps the connection open for 5 seconds.
# The server (with its 3-second timeout) should kick us
# before the 5 seconds are up.
sleep 5 | netcat localhost 6379 > $TEST_ACTUAL

echo "---  Comparing Results ---"
if diff -q $TEST_EXPECTED $TEST_ACTUAL; then
    echo "  PASSED: Server correctly disconnected idle client."
else
    echo "  FAILED: Idle test output MISMATCH!"
    echo "--- EXPECTED ---"
    cat $TEST_EXPECTED
    echo ""
    echo "--- ACTUAL ---"
    cat $TEST_ACTUAL
    exit 1 
fi

# Trap will run and kill the server
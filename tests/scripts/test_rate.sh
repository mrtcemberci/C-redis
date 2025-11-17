# This script tests the Rate Limiting and IP Ban functionality.
#
# NOTE: This test requires server constants to be lowered:
#   RATE_LIMIT_CONNECTIONS = 5
#   BAN_DURATION_SECONDS = 4

set -e # Exit immediately if any command fails

echo "---  Starting Server in Background (with low limits) ---"
./redis-clone > server.log 2>&1 &
SERVER_PID=$!
trap "echo '--- Shutting Down Server ---'; kill $SERVER_PID" EXIT
sleep 0.5 # Give server time to boot

# Define file paths
TEST_IN="tests/data/in/rate_test.in"
TEST_EXPECTED="tests/data/expected/rate_test.expected"
TEST_ACTUAL="tests/data/actual/rate_test.actual"

echo "---  Connecting 5 times (to fill quota) ---"
for i in 1 2 3 4 5
do
    # We pipe 'echo' to send a newline.
    # This simulates a "valid" connection that just disconnects.
    echo | netcat -w 1 localhost 6379 > /dev/null
done
echo "  Quota filled."

echo "---  Connecting 6th time (to trigger ban) ---"
echo | netcat -w 1 localhost 6379 > /dev/null
echo "  Ban triggered."

echo "---  Connecting 7th time (to test ban) ---"
# This netcat will be *force-closed* by the server.
# The 'actual' file should be EMPTY.
netcat -w 1 localhost 6379 > $TEST_ACTUAL || true
# We use '|| true' so the script doesn't exit if netcat fails

if [ -s $TEST_ACTUAL ]; then
    echo "  FAILED: Server responded, but should have been banned."
    echo "--- ACTUAL (should be empty) ---"
    cat $TEST_ACTUAL
    exit 1
else
    echo "  PASSED: Server correctly denied banned IP."
fi

# Wait for ban to expire
BAN_DURATION=6
echo "---  Waiting ${BAN_DURATION}s for ban to expire ---"
sleep $BAN_DURATION

echo "---  Connecting 8th time (to test expiry) ---"
# This connection should SUCCEED.
# We send a real command and check the real output.
cat $TEST_IN | netcat -w 1 localhost 6379 > $TEST_ACTUAL

echo "---  Comparing Results ---"
if diff -q $TEST_EXPECTED $TEST_ACTUAL; then
    echo "  PASSED: Ban expired correctly, and server is responsive."
else
    echo "  FAILED: Ban expiry test MISMATCH!"
    echo "--- EXPECTED ---"
    cat $TEST_EXPECTED
    echo "--- ACTUAL ---"
    cat $TEST_ACTUAL
    exit 1 
fi

# Trap will run and kill the server
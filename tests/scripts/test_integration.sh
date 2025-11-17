#This is a generic input test to test basic functionality

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

TEST_IN="tests/data/in/basic_test.in"
TEST_EXPECTED="tests/data/expected/basic_test.expected"
TEST_ACTUAL="tests/data/actual/basic_test.actual"

# Simulate client, redirecte input into the netcat and redirect the output to the .actual file
echo "--- Running Integration Test (basic) ---"

cat $TEST_IN | netcat -w 1 localhost 6379 > $TEST_ACTUAL

echo "--- Comparing Results ---"
if diff -q $TEST_EXPECTED $TEST_ACTUAL; then
    echo "   PASSED: Output matches expected."
else
    echo "  FAILED: Output MISMATCH!"
    echo "--- EXPECTED ---"
    cat $TEST_EXPECTED
    echo "--- ACTUAL ---"
    cat $TEST_ACTUAL
    exit 1 
fi

# The 'trap' will now run and kill the server
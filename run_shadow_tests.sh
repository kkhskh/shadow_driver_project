#!/bin/bash
# run_tests.sh - Simple test script for shadow driver modules

# Check for root permissions
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Define paths - adjust these to match your actual paths
BASE_DIR="$PWD"
RECOVERY_DIR="$BASE_DIR/recovery_evaluator"
FAULT_DIR="$BASE_DIR/fault_injection"
SHADOW_DIR="$BASE_DIR/network_shadow"
APP_TEST_DIR="$BASE_DIR/app_test_harness"

# Create results directory
RESULTS_DIR="$BASE_DIR/test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"
echo "Test results will be saved to: $RESULTS_DIR"

# Unload any previously loaded modules
echo "Unloading any previously loaded modules..."
rmmod app_test_harness 2>/dev/null
rmmod network_shadow 2>/dev/null
rmmod fault_injection 2>/dev/null
rmmod recovery_evaluator 2>/dev/null

# Skip rebuilding modules since they're already built
echo "Using pre-built modules..."

# Verify all required kernel modules exist
echo "Checking module files..."
if [ ! -f "$RECOVERY_DIR/recovery_evaluator.ko" ]; then
    echo "Error: $RECOVERY_DIR/recovery_evaluator.ko not found!"
    exit 1
fi

if [ ! -f "$FAULT_DIR/fault_injection.ko" ]; then
    echo "Error: $FAULT_DIR/fault_injection.ko not found!"
    exit 1
fi

if [ ! -f "$SHADOW_DIR/network_shadow.ko" ]; then
    echo "Error: $SHADOW_DIR/network_shadow.ko not found!"
    exit 1
fi

if [ ! -f "$APP_TEST_DIR/app_test_harness.ko" ]; then
    echo "Error: $APP_TEST_DIR/app_test_harness.ko not found!"
    exit 1
fi

# Load modules
echo "Loading modules..."
insmod "$RECOVERY_DIR/recovery_evaluator.ko"
if [ $? -ne 0 ]; then
    echo "Failed to load recovery_evaluator module!"
    exit 1
fi

insmod "$FAULT_DIR/fault_injection.ko"
if [ $? -ne 0 ]; then
    echo "Failed to load fault_injection module!"
    exit 1
fi

insmod "$SHADOW_DIR/network_shadow.ko" device=eth0
if [ $? -ne 0 ]; then
    echo "Failed to load network_shadow module!"
    exit 1
fi

insmod "$APP_TEST_DIR/app_test_harness.ko"
if [ $? -ne 0 ]; then
    echo "Failed to load app_test_harness module!"
    exit 1
fi

# Check that all modules loaded correctly
echo "Checking that modules are loaded..."
lsmod | grep -E 'app_test|fault|shadow|recovery'

# Enable fault injection
echo "Enabling fault injection..."
echo "enable" > /proc/fault_injection

# Run a basic test (mp3_player)
echo "Starting mp3_player test..."
echo "start 0" > /proc/app_test_harness
sleep 10  # Run for 10 seconds

# Check status
echo "App Test Harness Status:"
cat /proc/app_test_harness

# Save results
cat /proc/app_test_harness > "$RESULTS_DIR/app_test_status.txt"
cat /proc/fault_injection > "$RESULTS_DIR/fault_injection_status.txt"
if [ -f /proc/recovery_evaluator ]; then
    cat /proc/recovery_evaluator > "$RESULTS_DIR/recovery_evaluator_status.txt"
else
    echo "Note: /proc/recovery_evaluator not available"
fi

# Stop the test
echo "Stopping test..."
echo "stop" > /proc/app_test_harness

# Try specific fault injections
echo "Testing specific fault injection..."
echo "inject_specific e1000 0" > /proc/fault_injection

# Unload modules
echo "Unloading modules..."
rmmod app_test_harness
rmmod network_shadow
rmmod fault_injection
rmmod recovery_evaluator

echo "Test completed. Results saved to $RESULTS_DIR"
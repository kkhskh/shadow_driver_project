#!/bin/bash
# run_shadow_tests.sh - Automated testing script for shadow driver project
# Usage: sudo ./run_shadow_tests.sh [test_type] [duration]
#   test_type: all, mp3, audio, network, file, compiler, database (default: all)
#   duration: number of seconds to run each test (default: 30)

# Check for root permissions
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Default parameters
TEST_TYPE="all"
TEST_DURATION=30

# Parse command-line arguments
if [ -n "$1" ]; then
    TEST_TYPE="$1"
fi
if [ -n "$2" ]; then
    TEST_DURATION="$2"
fi

# Set the project directory path
PROJECT_DIR="$(pwd)"
echo "Project directory: $PROJECT_DIR"

# Create results directory
RESULTS_DIR="$PROJECT_DIR/test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"
echo "Test results will be saved to: $RESULTS_DIR"

# Function to save current status
save_status() {
    echo "Saving current status..."
    if [ -f /proc/app_test_harness ]; then
        cat /proc/app_test_harness > "$RESULTS_DIR/app_test_status_$1.txt"
    fi
    if [ -f /proc/fault_injection ]; then
        cat /proc/fault_injection > "$RESULTS_DIR/fault_injection_status_$1.txt"
    fi
    if [ -f /proc/recovery_evaluator ]; then
        cat /proc/recovery_evaluator > "$RESULTS_DIR/recovery_evaluator_status_$1.txt"
    fi
    dmesg | grep -E 'fault|shadow|recovery' > "$RESULTS_DIR/kernel_log_$1.txt"
}

# Function to run a specific test
run_test() {
    local app_idx=$1
    local app_name=$2
    local duration=$3
    
    echo "==============================================="
    echo "Starting test for $app_name (index: $app_idx)"
    echo "Test will run for $duration seconds"
    echo "==============================================="
    
    # Start the test
    echo "start $app_idx" > /proc/app_test_harness
    
    # Run for specified duration
    echo "Test running... (press Ctrl+C to interrupt)"
    for ((i=1; i<=duration; i++)); do
        echo -ne "Progress: $i/$duration seconds\r"
        sleep 1
    done
    echo -e "\nTest completed after $duration seconds"
    
    # Check status
    echo "Current test status:"
    cat /proc/app_test_harness
    
    # Stop the test
    echo "stop" > /proc/app_test_harness
    
    # Save results
    save_status "${app_name}"
    
    echo "Test for $app_name completed"
    echo "==============================================="
    echo
}

# Unload any previously loaded modules
echo "Unloading any previously loaded modules..."
rmmod app_test_harness 2>/dev/null
rmmod network_shadow 2>/dev/null
rmmod fault_injection 2>/dev/null
rmmod recovery_evaluator 2>/dev/null

# Log starting point in dmesg
echo "Shadow Driver Testing Started at $(date)" > /dev/kmsg

# Build all modules if they exist
echo "Building all modules..."
if [ -d "$PROJECT_DIR/recovery_evaluator" ]; then
    cd "$PROJECT_DIR/recovery_evaluator"
    make clean && make
else
    echo "Warning: recovery_evaluator directory not found"
fi

if [ -d "$PROJECT_DIR/fault_injection" ]; then
    cd "$PROJECT_DIR/fault_injection"
    make clean && make
else
    echo "Warning: fault_injection directory not found"
fi

if [ -d "$PROJECT_DIR/network_shadow" ]; then
    cd "$PROJECT_DIR/network_shadow"
    make clean && make
else
    echo "Warning: network_shadow directory not found"
fi

if [ -d "$PROJECT_DIR/app_test_harness" ]; then
    cd "$PROJECT_DIR/app_test_harness"
    make clean && make
else
    echo "Warning: app_test_harness directory not found"
fi

# Return to the project directory
cd "$PROJECT_DIR"

# Load modules - adjust paths based on where the .ko files are
echo "Loading modules..."
if [ -f "$PROJECT_DIR/recovery_evaluator/recovery_evaluator.ko" ]; then
    insmod "$PROJECT_DIR/recovery_evaluator/recovery_evaluator.ko"
    if [ $? -ne 0 ]; then
        echo "Failed to load recovery_evaluator module!"
        exit 1
    fi
else
    echo "Error: recovery_evaluator.ko not found"
    exit 1
fi

if [ -f "$PROJECT_DIR/fault_injection/fault_injection.ko" ]; then
    insmod "$PROJECT_DIR/fault_injection/fault_injection.ko"
    if [ $? -ne 0 ]; then
        echo "Failed to load fault_injection module!"
        exit 1
    fi
else
    echo "Error: fault_injection.ko not found"
    exit 1
fi

if [ -f "$PROJECT_DIR/network_shadow/network_shadow.ko" ]; then
    insmod "$PROJECT_DIR/network_shadow/network_shadow.ko" device=eth0
    if [ $? -ne 0 ]; then
        echo "Failed to load network_shadow module!"
        exit 1
    fi
else
    echo "Error: network_shadow.ko not found"
    exit 1
fi

if [ -f "$PROJECT_DIR/app_test_harness/app_test_harness.ko" ]; then
    insmod "$PROJECT_DIR/app_test_harness/app_test_harness.ko"
    if [ $? -ne 0 ]; then
        echo "Failed to load app_test_harness module!"
        exit 1
    fi
else
    echo "Error: app_test_harness.ko not found"
    exit 1
fi

# Check that all modules loaded correctly
echo "Checking that modules are loaded..."
lsmod | grep -E 'app_test|fault|shadow|recovery'
if [ $? -ne 0 ]; then
    echo "Some modules failed to load properly!"
    exit 1
fi

# Enable fault injection
echo "Enabling fault injection..."
echo "enable" > /proc/fault_injection

# Save initial status
save_status "initial"

# Run the appropriate tests
case "$TEST_TYPE" in
    "mp3")
        run_test 0 "mp3_player" $TEST_DURATION
        ;;
    "audio")
        run_test 1 "audio_recorder" $TEST_DURATION
        ;;
    "network")
        run_test 2 "network_file_transfer" $TEST_DURATION
        ;;
    "file")
        run_test 2 "network_file_transfer" $TEST_DURATION
        ;;
    "analyzer")
        run_test 3 "network_analyzer" $TEST_DURATION
        ;;
    "compiler")
        run_test 4 "compiler" $TEST_DURATION
        ;;
    "database")
        run_test 5 "database" $TEST_DURATION
        ;;
    "all")
        run_test 0 "mp3_player" $TEST_DURATION
        run_test 1 "audio_recorder" $TEST_DURATION
        run_test 2 "network_file_transfer" $TEST_DURATION
        run_test 3 "network_analyzer" $TEST_DURATION
        run_test 4 "compiler" $TEST_DURATION
        run_test 5 "database" $TEST_DURATION
        ;;
    *)
        echo "Unknown test type: $TEST_TYPE"
        echo "Valid options: all, mp3, audio, network, file, analyzer, compiler, database"
        exit 1
        ;;
esac

# Try some specific fault injections
echo "Testing specific fault injections..."
echo "inject_specific e1000 0" > /proc/fault_injection
sleep 1
echo "inject_specific snd 1" > /proc/fault_injection
sleep 1
echo "inject_specific ide 2" > /proc/fault_injection
sleep 1

# Save final status
save_status "final"

# Unload modules
echo "Unloading modules..."
rmmod app_test_harness
rmmod network_shadow
rmmod fault_injection
rmmod recovery_evaluator

# Create summary report
echo "Creating summary report..."
{
    echo "Shadow Driver Test Summary"
    echo "=========================="
    echo "Test run on: $(date)"
    echo "Test type: $TEST_TYPE"
    echo "Test duration: $TEST_DURATION seconds per application"
    echo ""
    
    # Extract and summarize test results
    echo "Test Results:"
    if [ -f "$RESULTS_DIR/app_test_status_final.txt" ]; then
        grep -A 20 "App Test Harness Status" "$RESULTS_DIR/app_test_status_final.txt" | grep -E "App [0-9]|Running|Trials|Recovery"
    else
        echo "No final app test status available"
    fi
    
    echo ""
    echo "Fault Injection Stats:"
    if [ -f "$RESULTS_DIR/fault_injection_status_final.txt" ]; then
        grep -A 5 "Fault Injection Status" "$RESULTS_DIR/fault_injection_status_final.txt"
    else
        echo "No final fault injection status available"
    fi
    
    echo ""
    echo "See the detailed logs in the $RESULTS_DIR directory for more information."
} > "$RESULTS_DIR/summary_report.txt"

echo "Testing completed! Summary report saved to $RESULTS_DIR/summary_report.txt"
cat "$RESULTS_DIR/summary_report.txt"
/*
 * recovery_evaluator.c - Tool to evaluate shadow driver recovery
 *
 * Based on concepts from "Recovering Device Drivers" by Swift et al.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/stdarg.h>

/* Maximum number of test cases to store */
#define MAX_TEST_CASES 50

/* Maximum test case name length */
#define MAX_TEST_NAME 64

/* Recovery phases */
enum recovery_phase {
    PHASE_NONE = 0,           /* No recovery in progress */
    PHASE_FAILURE_DETECTED,   /* Failure has been detected */
    PHASE_DRIVER_STOPPED,     /* Driver has been stopped */
    PHASE_DRIVER_RESTARTING,  /* Driver is being restarted */
    PHASE_RECOVERY_COMPLETE,  /* Recovery has completed successfully */
    PHASE_RECOVERY_FAILED     /* Recovery has failed */
};

/* Structure to track recovery events */
struct recovery_event {
    unsigned long timestamp;        /* Time event occurred */
    enum recovery_phase phase;      /* Recovery phase */
    char description[128];          /* Event description */
};

/* Maximum number of events per recovery */
#define MAX_EVENTS 50

/* Structure to track a recovery test case */
struct recovery_test {
    char name[MAX_TEST_NAME];       /* Test case name */
    char driver[64];                /* Driver being tested */
    unsigned long start_time;       /* When test started */
    unsigned long end_time;         /* When test completed */
    bool completed;                 /* Whether test completed */
    bool success;                   /* Whether recovery succeeded */
    
    /* Recovery events */
    struct recovery_event events[MAX_EVENTS];
    int num_events;
    
    /* Performance metrics */
    unsigned long detection_time;   /* Time to detect failure (jiffies) */
    unsigned long recovery_time;    /* Time to recover (jiffies) */
    unsigned long downtime;         /* Total driver downtime (jiffies) */
    
    /* Linked list */
    struct list_head list;
};

/* Global state */
static LIST_HEAD(test_cases);
static int num_test_cases = 0;
static struct recovery_test *current_test = NULL;
static spinlock_t test_lock;
static struct proc_dir_entry *recovery_proc_entry;

/* Function declarations - these aren't static because they're exported */
int add_event(struct recovery_test *test, enum recovery_phase phase, 
              const char *fmt, ...);
int start_test(const char *name, const char *driver);
int end_test(bool success);

/**
 * start_test - Start a new recovery test
 * @name: Name of the test
 * @driver: Name of the driver being tested
 *
 * Begins a new recovery test case
 */
int start_test(const char *name, const char *driver)
{
    struct recovery_test *test;
    unsigned long flags;
    
    /* Allocate test structure */
    test = kmalloc(sizeof(*test), GFP_KERNEL);
    if (!test)
        return -ENOMEM;
    
    /* Initialize test */
    memset(test, 0, sizeof(*test));
    strncpy(test->name, name, MAX_TEST_NAME - 1);
    strncpy(test->driver, driver, sizeof(test->driver) - 1);
    test->start_time = jiffies;
    test->completed = false;
    test->success = false;
    test->num_events = 0;
    
    /* Add to list */
    spin_lock_irqsave(&test_lock, flags);
    
    if (current_test) {
        /* If there's a current test, mark it as incomplete */
        current_test->completed = false;
        current_test->end_time = jiffies;
        add_event(current_test, PHASE_NONE, "Test interrupted by new test");
    }
    
    if (num_test_cases >= MAX_TEST_CASES) {
        /* Remove oldest test case */
        struct recovery_test *oldest;
        oldest = list_first_entry_or_null(&test_cases, struct recovery_test, list);
        if (oldest) {
            list_del(&oldest->list);
            kfree(oldest);
            num_test_cases--;
        }
    }
    
    list_add_tail(&test->list, &test_cases);
    num_test_cases++;
    current_test = test;
    
    spin_unlock_irqrestore(&test_lock, flags);
    
    printk(KERN_INFO "Recovery evaluator: Started test '%s' for driver '%s'\n",
           name, driver);
    
    return 0;
}
EXPORT_SYMBOL(start_test);

/**
 * add_event - Add an event to the current test
 * @test: Test to add event to, or NULL for current test
 * @phase: Recovery phase
 * @fmt: printf-style format string
 * @...: Format arguments
 *
 * Records an event in the recovery process
 */
int add_event(struct recovery_test *test, enum recovery_phase phase, 
              const char *fmt, ...)
{
    struct recovery_event *event;
    va_list args;
    unsigned long flags;
    
    /* Use current test if none specified */
    if (!test)
        test = current_test;
    
    if (!test)
        return -EINVAL;
    
    spin_lock_irqsave(&test_lock, flags);
    
    /* Check if we have room for more events */
    if (test->num_events >= MAX_EVENTS) {
        spin_unlock_irqrestore(&test_lock, flags);
        return -ENOSPC;
    }
    
    /* Add the event */
    event = &test->events[test->num_events++];
    event->timestamp = jiffies;
    event->phase = phase;
    
    /* Format the description */
    va_start(args, fmt);
    vsnprintf(event->description, sizeof(event->description), fmt, args);
    va_end(args);
    
    /* Update test state based on phase */
    switch (phase) {
    case PHASE_FAILURE_DETECTED:
        /* Record time of failure detection */
        test->detection_time = jiffies - test->start_time;
        break;
        
    case PHASE_RECOVERY_COMPLETE:
        /* Record recovery completion */
        test->end_time = jiffies;
        test->completed = true;
        test->success = true;
        test->recovery_time = jiffies - 
                              (test->start_time + test->detection_time);
        test->downtime = jiffies - (test->start_time + test->detection_time);
        break;
        
    case PHASE_RECOVERY_FAILED:
        /* Record recovery failure */
        test->end_time = jiffies;
        test->completed = true;
        test->success = false;
        test->recovery_time = jiffies - 
                              (test->start_time + test->detection_time);
        test->downtime = jiffies - (test->start_time + test->detection_time);
        break;
        
    default:
        /* Other phases just record the event */
        break;
    }
    
    spin_unlock_irqrestore(&test_lock, flags);
    
    printk(KERN_DEBUG "Recovery evaluator: [%s] %s\n", 
           test->name, event->description);
    
    return 0;
}
EXPORT_SYMBOL(add_event);

/**
 * end_test - End the current recovery test
 * @success: Whether recovery was successful
 *
 * Completes the current test case
 */
int end_test(bool success)
{
    unsigned long flags;
    
    spin_lock_irqsave(&test_lock, flags);
    
    if (!current_test) {
        spin_unlock_irqrestore(&test_lock, flags);
        return -EINVAL;
    }
    
    /* Update test state */
    current_test->end_time = jiffies;
    current_test->completed = true;
    current_test->success = success;
    
    /* Calculate metrics if not already done */
    if (current_test->downtime == 0) {
        current_test->downtime = jiffies - current_test->start_time;
    }
    
    /* Add an event */
    if (current_test->num_events < MAX_EVENTS) {
        struct recovery_event *event;
        event = &current_test->events[current_test->num_events++];
        event->timestamp = jiffies;
        event->phase = success ? PHASE_RECOVERY_COMPLETE : PHASE_RECOVERY_FAILED;
        snprintf(event->description, sizeof(event->description),
                "Test completed %s", success ? "successfully" : "with failures");
    }
    
    printk(KERN_INFO "Recovery evaluator: Ended test '%s' %s\n",
           current_test->name, success ? "successfully" : "with failures");
    
    /* Clear current test */
    current_test = NULL;
    
    spin_unlock_irqrestore(&test_lock, flags);
    
    return 0;
}
EXPORT_SYMBOL(end_test);

/**
 * recovery_proc_show - Display recovery test results
 * @m: Seq file to output to
 * @v: Unused
 *
 * Outputs recovery test results to /proc/recovery_evaluator
 */
static int recovery_proc_show(struct seq_file *m, void *v)
{
    struct recovery_test *test;
    unsigned long flags;
    int i;
    
    spin_lock_irqsave(&test_lock, flags);
    
    seq_printf(m, "Recovery Evaluator Status:\n");
    seq_printf(m, "  Number of test cases: %d\n", num_test_cases);
    seq_printf(m, "  Current test: %s\n", 
               current_test ? current_test->name : "None");
    
    seq_printf(m, "\nTest Cases:\n");
    list_for_each_entry(test, &test_cases, list) {
        /* Convert jiffies to more readable form */
        unsigned long detection_ms = jiffies_to_msecs(test->detection_time);
        unsigned long recovery_ms = jiffies_to_msecs(test->recovery_time);
        unsigned long downtime_ms = jiffies_to_msecs(test->downtime);
        
        seq_printf(m, "  Test: %s (Driver: %s)\n", test->name, test->driver);
        seq_printf(m, "    Status: %s\n", 
                  test->completed ? (test->success ? "Success" : "Failed") : "In progress");
        seq_printf(m, "    Duration: %lu ms\n", 
                  (unsigned long)jiffies_to_msecs(test->end_time - test->start_time));
        
        if (test->completed) {
            seq_printf(m, "    Detection time: %lu ms\n", detection_ms);
            seq_printf(m, "    Recovery time: %lu ms\n", recovery_ms);
            seq_printf(m, "    Total downtime: %lu ms\n", downtime_ms);
        }
        
        seq_printf(m, "    Events:\n");
        for (i = 0; i < test->num_events; i++) {
            struct recovery_event *event = &test->events[i];
            unsigned long event_time = jiffies_to_msecs(event->timestamp - test->start_time);
            
            seq_printf(m, "      [%lu ms] %s\n", 
                      event_time, event->description);
        }
        
        seq_printf(m, "\n");
    }
    
    spin_unlock_irqrestore(&test_lock, flags);
    
    return 0;
}

/**
 * recovery_proc_open - Open handler for proc file
 * @inode: Inode
 * @file: File
 *
 * Opens the proc file for reading
 */
static int recovery_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, recovery_proc_show, NULL);
}

/**
 * recovery_proc_write - Write handler for proc file
 * @file: File being written to
 * @buffer: User data
 * @count: Number of bytes
 * @ppos: Position in file
 *
 * Handles commands written to the proc file
 */
static ssize_t recovery_proc_write(struct file *file, const char __user *buffer,
                                 size_t count, loff_t *ppos)
{
    char cmd[128];
    size_t cmd_size = min(count, sizeof(cmd) - 1);
    
    if (copy_from_user(cmd, buffer, cmd_size))
        return -EFAULT;
    
    cmd[cmd_size] = '\0';
    
    /* Process commands */
    if (strncmp(cmd, "start ", 6) == 0) {
        char test_name[MAX_TEST_NAME];
        char driver_name[64];
        
        if (sscanf(cmd + 6, "%63s %63s", test_name, driver_name) == 2) {
            start_test(test_name, driver_name);
        }
    } else if (strncmp(cmd, "end ", 4) == 0) {
        bool success = false;
        char result[16];
        
        if (sscanf(cmd + 4, "%15s", result) == 1) {
            if (strcmp(result, "success") == 0)
                success = true;
            
            end_test(success);
        }
    } else if (strncmp(cmd, "event ", 6) == 0) {
        char phase_str[32];
        char desc[128];
        enum recovery_phase phase = PHASE_NONE;
        
        if (sscanf(cmd + 6, "%31s %127[^\n]", phase_str, desc) == 2) {
            /* Map string to phase */
            if (strcmp(phase_str, "failure") == 0)
                phase = PHASE_FAILURE_DETECTED;
            else if (strcmp(phase_str, "stopped") == 0)
                phase = PHASE_DRIVER_STOPPED;
            else if (strcmp(phase_str, "restarting") == 0)
                phase = PHASE_DRIVER_RESTARTING;
            else if (strcmp(phase_str, "complete") == 0)
                phase = PHASE_RECOVERY_COMPLETE;
            else if (strcmp(phase_str, "failed") == 0)
                phase = PHASE_RECOVERY_FAILED;
                
            add_event(NULL, phase, "%s", desc);
        }
    } else if (strncmp(cmd, "clear", 5) == 0) {
        /* Clear all test cases */
        struct recovery_test *test, *tmp;
        unsigned long flags;
        
        spin_lock_irqsave(&test_lock, flags);
        
        list_for_each_entry_safe(test, tmp, &test_cases, list) {
            list_del(&test->list);
            kfree(test);
        }
        
        num_test_cases = 0;
        current_test = NULL;
        
        spin_unlock_irqrestore(&test_lock, flags);
        
        printk(KERN_INFO "Recovery evaluator: Cleared all test cases\n");
    } else {
        printk(KERN_WARNING "Recovery evaluator: Unknown command: %s\n", cmd);
    }
    
    return count;
}

/* File operations for the proc file */
static const struct file_operations recovery_proc_fops = {
    .owner = THIS_MODULE,
    .open = recovery_proc_open,
    .read = seq_read,
    .write = recovery_proc_write,
    .llseek = seq_lseek,
    .release = single_release
};

/**
 * init_recovery_evaluator - Initialize the recovery evaluator
 *
 * Sets up proc file and data structures
 */
static int __init init_recovery_evaluator(void)
{
    /* Initialize lock */
    spin_lock_init(&test_lock);
    
    /* Create proc entry */
    recovery_proc_entry = proc_create("recovery_evaluator", 0644, NULL, 
                                     &recovery_proc_fops);
    if (!recovery_proc_entry) {
        printk(KERN_ERR "Failed to create /proc/recovery_evaluator\n");
        return -ENOMEM;
    }
    
    printk(KERN_INFO "Recovery evaluator module loaded\n");
    printk(KERN_INFO "Use /proc/recovery_evaluator to monitor recovery tests\n");
    
    return 0;
}

/**
 * cleanup_recovery_evaluator - Clean up the recovery evaluator
 *
 * Removes proc file and frees resources
 */
static void __exit cleanup_recovery_evaluator(void)
{
    struct recovery_test *test, *tmp;
    
    /* Remove proc entry */
    if (recovery_proc_entry)
        proc_remove(recovery_proc_entry);
    
    /* Free test cases */
    list_for_each_entry_safe(test, tmp, &test_cases, list) {
        list_del(&test->list);
        kfree(test);
    }
    
    printk(KERN_INFO "Recovery evaluator module unloaded\n");
}

module_init(init_recovery_evaluator);
module_exit(cleanup_recovery_evaluator);

MODULE_AUTHOR("Based on Swift et al.");
MODULE_DESCRIPTION("Tool to evaluate shadow driver recovery");
MODULE_LICENSE("GPL");
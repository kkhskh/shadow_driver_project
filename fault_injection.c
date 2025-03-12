/*
 * fault_injection.c - Fault injection framework for testing shadow drivers
 *
 * Based on concepts from "Recovering Device Drivers" by Swift et al.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

/* Fault types that can be injected */
enum fault_type {
    FAULT_NULL_POINTER    = 0,  /* Dereference a null pointer */
    FAULT_INVALID_MEMORY  = 1,  /* Access invalid memory */
    FAULT_INFINITE_LOOP   = 2,  /* Enter an infinite loop */
    FAULT_SLEEP_IN_ATOMIC = 3,  /* Sleep in atomic context */
    FAULT_RESOURCE_LEAK   = 4,  /* Leak a resource (memory, etc.) */
    FAULT_CORRUPT_DATA    = 5,  /* Corrupt internal data structure */
    FAULT_BAD_PARAMETER   = 6,  /* Pass bad parameters to kernel */
    FAULT_HANG            = 7,  /* Just hang the driver */
    FAULT_MAX             = 8   /* Number of fault types */
};

/* Structure to track fault injection settings */
struct fault_control {
    bool enabled;                /* Main switch for fault injection */
    unsigned long interval_min;  /* Minimum interval between faults (jiffies) */
    unsigned long interval_max;  /* Maximum interval between faults (jiffies) */
    unsigned int probability;    /* Probability (0-100) of injecting fault when eligible */
    bool specific_fault_enabled[FAULT_MAX]; /* Enable/disable specific fault types */
    unsigned int fault_weights[FAULT_MAX];  /* Relative probability of each fault */
    char target_driver[64];      /* Name of driver to target */
    
    /* Statistics */
    unsigned long faults_injected;
    unsigned long faults_by_type[FAULT_MAX];
    unsigned long last_fault_time;
    enum fault_type last_fault_type;
};

/* Global fault control state */
static struct fault_control fault_ctrl = {
    .enabled = false,
    .interval_min = HZ * 10,    /* 10 seconds minimum */
    .interval_max = HZ * 60,    /* 60 seconds maximum */
    .probability = 10,          /* 10% chance by default */
    .specific_fault_enabled = {true, true, true, true, true, true, true, true},
    .fault_weights = {10, 10, 10, 10, 10, 10, 10, 10},  /* Equal weight initially */
    .target_driver = "e1000",   /* Default target */
    .faults_injected = 0,
};

/* Forward declarations */
static void inject_random_fault(void);
static void schedule_fault_injection(void);

/* Timer for scheduling fault injection */
static struct timer_list fault_timer;

/**
 * fault_timer_callback - Timer callback to trigger fault injection
 * @data: Unused timer data
 *
 * Called when the fault injection timer expires
 */
static void fault_timer_callback(unsigned long data)
{
    if (fault_ctrl.enabled) {
        /* Determine if we should inject a fault based on probability */
        unsigned int rand;
        get_random_bytes(&rand, sizeof(rand));
        rand = rand % 100;
        
        if (rand < fault_ctrl.probability) {
            /* Time to inject a fault */
            inject_random_fault();
        }
        
        /* Schedule the next potential fault */
        schedule_fault_injection();
    }
}

/**
 * schedule_fault_injection - Schedule the next potential fault
 *
 * Sets up timer for next fault injection opportunity
 */
static void schedule_fault_injection(void)
{
    unsigned long interval;
    unsigned int rand;
    
    if (!fault_ctrl.enabled)
        return;
    
    /* Calculate a random interval between min and max */
    get_random_bytes(&rand, sizeof(rand));
    interval = fault_ctrl.interval_min + 
               (rand % (fault_ctrl.interval_max - fault_ctrl.interval_min + 1));
    
    /* Set up the timer */
    mod_timer(&fault_timer, jiffies + interval);
    
    printk(KERN_DEBUG "Fault injection: Next fault opportunity in %lu jiffies\n", 
           interval);
}

/**
 * select_fault_type - Select a fault type to inject
 *
 * Uses the configured weights to select a fault type
 */
static enum fault_type select_fault_type(void)
{
    unsigned int total_weight = 0;
    unsigned int rand_val;
    unsigned int cumulative = 0;
    int i;
    
    /* Calculate total weight of enabled faults */
    for (i = 0; i < FAULT_MAX; i++) {
        if (fault_ctrl.specific_fault_enabled[i])
            total_weight += fault_ctrl.fault_weights[i];
    }
    
    if (total_weight == 0)
        return FAULT_NULL_POINTER;  /* Default if no faults enabled */
    
    /* Get a random value within the total weight */
    get_random_bytes(&rand_val, sizeof(rand_val));
    rand_val = rand_val % total_weight;
    
    /* Find the fault corresponding to this value */
    for (i = 0; i < FAULT_MAX; i++) {
        if (fault_ctrl.specific_fault_enabled[i]) {
            cumulative += fault_ctrl.fault_weights[i];
            if (rand_val < cumulative)
                return i;
        }
    }
    
    return FAULT_NULL_POINTER;  /* Shouldn't get here */
}

/**
 * inject_null_pointer - Dereference a null pointer
 */
static void inject_null_pointer(void)
{
    int *ptr = NULL;
    printk(KERN_DEBUG "Fault injection: Dereferencing NULL pointer\n");
    *ptr = 0;  /* This will crash */
}

/**
 * inject_invalid_memory - Access invalid memory
 */
static void inject_invalid_memory(void)
{
    int *ptr = (int *)0xBAD1DEA;
    printk(KERN_DEBUG "Fault injection: Accessing invalid memory\n");
    *ptr = 0;  /* This will crash */
}

/**
 * inject_infinite_loop - Create an infinite loop
 */
static void inject_infinite_loop(void)
{
    printk(KERN_DEBUG "Fault injection: Entering infinite loop\n");
    while (1) {
        /* Prevent compiler optimization */
        cpu_relax();
    }
}

/**
 * inject_sleep_in_atomic - Sleep in an atomic context
 */
static void inject_sleep_in_atomic(void)
{
    printk(KERN_DEBUG "Fault injection: Sleeping in atomic context\n");
    /* This is not allowed in interrupt context */
    msleep(1000);
}

/**
 * inject_resource_leak - Leak memory resources
 */
static void inject_resource_leak(void)
{
    void *ptr;
    int i;
    
    printk(KERN_DEBUG "Fault injection: Leaking memory resources\n");
    
    /* Allocate memory without freeing it */
    for (i = 0; i < 100; i++) {
        ptr = kmalloc(4096, GFP_KERNEL);
        /* Intentionally don't free */
    }
}

/**
 * inject_corrupt_data - Corrupt memory with bad data
 */
static void inject_corrupt_data(void)
{
    struct list_head *fake_list;
    
    printk(KERN_DEBUG "Fault injection: Corrupting data structures\n");
    
    /* Create an invalid list that will cause problems when traversed */
    fake_list = kmalloc(sizeof(*fake_list), GFP_KERNEL);
    if (fake_list) {
        /* Point to invalid memory */
        fake_list->next = (struct list_head *)0xDEADBEEF;
        fake_list->prev = (struct list_head *)0xBADCAFE;
        
        /* Note: we're leaking this memory, but it's intentional for the fault */
    }
}

/**
 * inject_bad_parameter - Pass bad parameters to kernel functions
 */
static void inject_bad_parameter(void)
{
    printk(KERN_DEBUG "Fault injection: Passing bad parameters\n");
    
    /* Call kernel function with bad params */
    kfree((void *)0x1);  /* Invalid pointer, will crash */
}

/**
 * inject_hang - Make the driver hang
 */
static void inject_hang(void)
{
    printk(KERN_DEBUG "Fault injection: Hanging the driver\n");
    
    /* Disable interrupts and enter tight loop */
    local_irq_disable();
    while (1) {
        cpu_relax();
    }
}

/**
 * inject_random_fault - Inject a randomly selected fault
 *
 * Selects and injects one of the configured fault types
 */
static void inject_random_fault(void)
{
    enum fault_type type;
    
    /* Skip if not enabled */
    if (!fault_ctrl.enabled)
        return;
    
    /* Select a fault type */
    type = select_fault_type();
    
    /* Record statistics */
    fault_ctrl.faults_injected++;
    fault_ctrl.faults_by_type[type]++;
    fault_ctrl.last_fault_time = jiffies;
    fault_ctrl.last_fault_type = type;
    
    printk(KERN_INFO "Fault injection: Injecting fault type %d into %s\n",
           type, fault_ctrl.target_driver);
    
    /* Inject the selected fault */
    switch (type) {
    case FAULT_NULL_POINTER:
        inject_null_pointer();
        break;
    case FAULT_INVALID_MEMORY:
        inject_invalid_memory();
        break;
    case FAULT_INFINITE_LOOP:
        inject_infinite_loop();
        break;
    case FAULT_SLEEP_IN_ATOMIC:
        inject_sleep_in_atomic();
        break;
    case FAULT_RESOURCE_LEAK:
        inject_resource_leak();
        break;
    case FAULT_CORRUPT_DATA:
        inject_corrupt_data();
        break;
    case FAULT_BAD_PARAMETER:
        inject_bad_parameter();
        break;
    case FAULT_HANG:
        inject_hang();
        break;
    default:
        printk(KERN_WARNING "Fault injection: Unknown fault type %d\n", type);
        break;
    }
}

/**
 * fault_proc_show - Display fault injection stats in proc fs
 * @m: Seq file to output to
 * @v: Unused
 *
 * Outputs fault injection statistics to /proc/fault_injection
 */
static int fault_proc_show(struct seq_file *m, void *v)
{
    int i;
    
    seq_printf(m, "Fault Injection Status:\n");
    seq_printf(m, "  Enabled:       %s\n", fault_ctrl.enabled ? "Yes" : "No");
    seq_printf(m, "  Target driver: %s\n", fault_ctrl.target_driver);
    seq_printf(m, "  Interval:      %lu - %lu jiffies\n", 
               fault_ctrl.interval_min, fault_ctrl.interval_max);
    seq_printf(m, "  Probability:   %u%%\n", fault_ctrl.probability);
    seq_printf(m, "  Faults injected: %lu\n", fault_ctrl.faults_injected);
    seq_printf(m, "  Last fault:      %lu jiffies ago (type %d)\n", 
               jiffies - fault_ctrl.last_fault_time, fault_ctrl.last_fault_type);
    
    seq_printf(m, "\nFault Types:\n");
    for (i = 0; i < FAULT_MAX; i++) {
        seq_printf(m, "  Type %d: %s (weight: %u, count: %lu)\n", 
                   i, 
                   fault_ctrl.specific_fault_enabled[i] ? "Enabled" : "Disabled",
                   fault_ctrl.fault_weights[i],
                   fault_ctrl.faults_by_type[i]);
    }
    
    return 0;
}

/**
 * fault_proc_open - Open handler for /proc/fault_injection
 * @inode: Proc inode
 * @file: File structure
 *
 * Opens the proc file and prepares for reading
 */
static int fault_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, fault_proc_show, NULL);
}

/* File operations for the /proc entry */
static const struct file_operations fault_proc_fops = {
    .owner   = THIS_MODULE,
    .open    = fault_proc_open,
    .read    = seq_read,
    .write   = fault_proc_write,
    .llseek  = seq_lseek,
    .release = single_release,
};

/* Proc entry */
static struct proc_dir_entry *fault_proc_entry;

/**
 * init_fault_injection - Initialize the fault injection system
 *
 * Sets up timers and proc filesystem entries
 */
static int __init init_fault_injection(void)
{
    /* Initialize the fault timer */
    setup_timer(&fault_timer, fault_timer_callback, 0);
    
    /* Create proc entry */
    fault_proc_entry = proc_create("fault_injection", 0644, NULL, &fault_proc_fops);
    if (!fault_proc_entry) {
        printk(KERN_ERR "Failed to create /proc/fault_injection\n");
        return -ENOMEM;
    }
    
    printk(KERN_INFO "Fault injection module loaded\n");
    printk(KERN_INFO "Use /proc/fault_injection to control fault injection\n");
    
    return 0;
}

/**
 * cleanup_fault_injection - Clean up fault injection system
 *
 * Removes timers and proc filesystem entries
 */
static void __exit cleanup_fault_injection(void)
{
    /* Disable fault injection */
    fault_ctrl.enabled = false;
    
    /* Delete timer */
    del_timer_sync(&fault_timer);
    
    /* Remove proc entry */
    if (fault_proc_entry)
        proc_remove(fault_proc_entry);
    
    printk(KERN_INFO "Fault injection module unloaded\n");
}

module_init(init_fault_injection);
module_exit(cleanup_fault_injection);

MODULE_AUTHOR("Based on Swift et al.");
MODULE_DESCRIPTION("Fault Injection Framework for Shadow Drivers");
MODULE_LICENSE("GPL");

/**
 * fault_proc_write - Write handler for /proc/fault_injection
 * @file: File structure
 * @buffer: User buffer containing data
 * @count: Number of bytes in buffer
 * @ppos: Position in file
 *
 * Handles commands written to /proc/fault_injection
 */
static ssize_t fault_proc_write(struct file *file, const char __user *buffer,
                                 size_t count, loff_t *ppos)
{
    char cmd[128];
    size_t cmd_size = min(count, sizeof(cmd) - 1);
    
    if (copy_from_user(cmd, buffer, cmd_size))
        return -EFAULT;
    
    cmd[cmd_size] = '\0';
    
    /* Process command */
    if (strncmp(cmd, "enable", 6) == 0) {
        fault_ctrl.enabled = true;
        schedule_fault_injection();
        printk(KERN_INFO "Fault injection: Enabled\n");
    } else if (strncmp(cmd, "disable", 7) == 0) {
        fault_ctrl.enabled = false;
        del_timer_sync(&fault_timer);
        printk(KERN_INFO "Fault injection: Disabled\n");
    } else if (strncmp(cmd, "trigger", 7) == 0) {
        /* Manually trigger a fault */
        inject_random_fault();
    } else if (strncmp(cmd, "target ", 7) == 0) {
        /* Set target driver */
        char driver_name[64];
        if (sscanf(cmd + 7, "%63s", driver_name) == 1) {
            strncpy(fault_ctrl.target_driver, driver_name, 
                    sizeof(fault_ctrl.target_driver) - 1);
            fault_ctrl.target_driver[sizeof(fault_ctrl.target_driver) - 1] = '\0';
            printk(KERN_INFO "Fault injection: Target set to %s\n", 
                   fault_ctrl.target_driver);
        }
    } else if (strncmp(cmd, "probability ", 12) == 0) {
        /* Set fault probability */
        unsigned int prob;
        if (sscanf(cmd + 12, "%u", &prob) == 1 && prob <= 100) {
            fault_ctrl.probability = prob;
            printk(KERN_INFO "Fault injection: Probability set to %u%%\n", 
                   fault_ctrl.probability);
        }
    } else if (strncmp(cmd, "interval ", 9) == 0) {
        /* Set fault interval */
        unsigned long min, max;
        if (sscanf(cmd + 9, "%lu %lu", &min, &max) == 2 && min <= max) {
            fault_ctrl.interval_min = min;
            fault_ctrl.interval_max = max;
            printk(KERN_INFO "Fault injection: Interval set to %lu-%lu jiffies\n", 
                   fault_ctrl.interval_min, fault_ctrl.interval_max);
        }
    } else if (strncmp(cmd, "fault_type ", 11) == 0) {
        /* Enable/disable specific fault type */
        unsigned int type;
        char action[16];
        if (sscanf(cmd + 11, "%u %15s", &type, action) == 2 && type < FAULT_MAX) {
            if (strncmp(action, "enable", 6) == 0) {
                fault_ctrl.specific_fault_enabled[type] = true;
                printk(KERN_INFO "Fault injection: Enabled fault type %u\n", type);
            } else if (strncmp(action, "disable", 7) == 0) {
                fault_ctrl.specific_fault_enabled[type] = false;
                printk(KERN_INFO "Fault injection: Disabled fault type %u\n", type);
            }
        }
    } else if (strncmp(cmd, "weight ", 7) == 0) {
        /* Set weight for specific fault type */
        unsigned int type, weight;
        if (sscanf(cmd + 7, "%u %u", &type, &weight) == 2 && type < FAULT_MAX) {
            fault_ctrl.fault_weights[type] = weight;
            printk(KERN_INFO "Fault injection: Set weight %u for fault type %u\n", 
                   weight, type);
        }
    } else {
        printk(KERN_WARNING "Fault injection: Unknown command: %s\n", cmd);
    }
    
    return count;
}
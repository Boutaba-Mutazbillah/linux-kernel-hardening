# Comprehensive Architecture: Synchronous System Call Interception Subsystem (LKM)

## 1. Architectural Architecture & Core Mechanism
This documentation details the engineering requirements for building a lightweight Linux Kernel Module (LKM) designed for synchronous system call interception (Syscall Hooking) within Ring 0 memory space. The implementation does not replace or modify the core monolithic kernel structure; instead, it injects a control routing primitive into the active system call table (`sys_call_table`) residing in volatile system memory.

The redirection sequence executes through a four-stage volatile memory state alteration:
* **Symbol Resolution:** The module invokes internal kernel lookup interfaces (`kallsyms_lookup_name`) to resolve the absolute virtual memory address of the target `sys_call_table`.
* **Control Register Override:** It modifies the CPU architectures' execution parameters by clearing the Write-Protect (WP) bit (Bit 16) of the `CR0` processor control register. This action temporarily grants write-privileges to read-only protected kernel memory pages.
* **Atomic Pointer Substitution:** The entry corresponding to the targeted identifier (`__NR_mkdir`) is extracted, cached securely as a backup pointer, and hot-swapped with the custom memory pointer referencing `boutaba_hooked_mkdir`.
* **State Restoration:** The WP bit in the `CR0` register is immediately re-enabled, restoring the strict read-only page table protection to maintain structural integrity against outside modifications.

---

## 2. Low-Level Core Code (Linux-LKM_SysInterceptor.c)

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

unsigned long *sys_call_table_ptr;
asmlinkage long (*original_mkdir)(const char __user *pathname, umode_t mode);

asmlinkage long boutaba_hooked_mkdir(const char __user *pathname, umode_t mode) {
    char buf;
    if (copy_from_user(&buf, pathname, sizeof(buf) - 1) == 0) {
        buf[sizeof(buf) - 1] = '\0';
        if (strcmp(&buf, "block_dir") == 0) {
            return -EACCES;
        }
    }
    return original_mkdir(pathname, mode);
}

static int __init Linux_LKM_SysInterceptor_init(void) {
    sys_call_table_ptr = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table_ptr) return -EINVAL;

    original_mkdir = (void *)sys_call_table_ptr[__NR_mkdir];

    write_cr0(read_cr0() & ~0x00010000);
    sys_call_table_ptr[__NR_mkdir] = (unsigned long)boutaba_hooked_mkdir;
    write_cr0(read_cr0() | 0x00010000);

    return 0;
}

static void __exit Linux_LKM_SysInterceptor_exit(void) {
    if (sys_call_table_ptr && original_mkdir) {
        write_cr0(read_cr0() & ~0x00010000);
        sys_call_table_ptr[__NR_mkdir] = (unsigned long)original_mkdir;
        write_cr0(read_cr0() | 0x00010000);
    }
}

module_init(Linux_LKM_SysInterceptor_init);
module_exit(Linux_LKM_SysInterceptor_exit);
```

---

## 3. Deep Component Dissection & Code Explanation

### Section A: Header Includes & Architectural Specifications
This segment binds the subsystem to the Linux kernel execution core and defines its environmental boundaries:
* **`linux/init.h` & `linux/module.h`:** Compulsory interfaces required to interpret module macros, handling instantiation and removal lifecycles (`module_init` and `module_exit`).
* **`linux/unistd.h`:** Provides the architecture-specific vector table offsets and indexes for system calls (resolving the literal definition of `__NR_mkdir`).
* **`linux/kallsyms.h`:** Exposes kernel symbol resolution routines, allowing the subsystem to query runtime virtual memory maps for unexported pointers.
* **`linux/uaccess.h`:** Encapsulates memory barrier verification wrappers required to transition variables across the rigid User-Space to Kernel-Space boundary.
* **`MODULE_LICENSE("GPL")`:** Mandatory structural declaration. Omitting this parameter taints the kernel, causing the subsystem insertion to fail.

### Section B: Synchronous Interception Logic (The Hook)
The active security enforcement agent handling request evaluation and structural dropping:
* **`boutaba_hooked_mkdir`:** Functions as an inline proxy routine, capturing raw parameters passed from non-privileged contexts before they reach storage controllers.
* **`copy_from_user`:** Safely mirrors strings out of untrusted user memory pages into localized supervisor cache to mitigate potential Time-of-Check to Time-of-Use (TOCTOU) exploits.
* **`strcmp` Evaluation:** Runs a quiet validation scan against the localized buffer to intercept requests matching the hardcoded literal token `block_dir`.
* **Sub-Ring Rejection:** If a token match is found, execution cuts short and drops out, passing an explicit `-EACCES` error state back up the stack. This terminates the action silently without writing warnings to host logs.
* **Pass-Through Execution:** Compliant queries bypass the string validation path and drop directly into the cached pointer referencing `original_mkdir`.

### Section C: Initialization & Runtime Page Invalidation
Handles supervisor memory manipulation routines upon module insertion:
* **Table Identification:** Invokes `Linux_LKM_SysInterceptor_init` to retrieve the baseline index vector map of `sys_call_table` from the operating systems' live memory map.
* **State Preservation:** Backs up the genuine address of the target index to prevent missing reference pointers during hardware cleanups.
* **Hardware Interlocking Override:** Clears Bit 16 of the CPU architecture's `CR0` control register. This disables memory write-protection flags across all page entries.
* **Pointer Substitution:** Injects the virtual memory address of the custom hooking code directly into the slot designated for the core system call.
* **Memory Protection Re-Locking:** Forces Bit 16 of `CR0` back to an active state, blocking secondary runtime scripts from modifying system pointers.

### Section D: Destructor & Vector Reversion
Handles state de-allocation and system restoration during module removal:
* **Pointer Validation:** Checks active pointers against NULL states to ensure structural modification steps can execute safely.
* **Temporary Page Invalidation:** Drops memory read-only flags using the `CR0` register manipulation routing to allow write access.
* **Table Alignment Restoration:** Overwrites the custom hook pointer inside the system call array with the original system address saved during startup.
* **Final Hardware Locking:** Re-locks page table variables to preserve vanilla system behavior and free supervisor resources completely.

---

## 4. Native Compilation & Deployment Manual
Compilation requires native development headers configured for the exact target kernel architecture.

### Build Engine Configuration (Makefile)
```makefile
obj-m += Linux-LKM_SysInterceptor.o
all:
	make -C /lib/modules/(shell uname -r)/build M=(PWD) modules
clean:
	make -C /lib/modules/(shell uname -r)/build M=(PWD) clean
```

### Verification & Operations Pipeline
Execute compilation and deployment directly within a root-privileged shell terminal:

```bash
# Execute local toolchain to build the binary kernel object (.ko)
make

# Dynamically link and load the compiled module into supervisor space
sudo insmod Linux-LKM_SysInterceptor.ko

# Test the active boundary policy (this directory creation must fail)
mkdir block_dir

# Test normal functionality (this directory creation must succeed)
mkdir safe_dir

# Terminate execution, safely revert pointers, and unload the module
sudo rmmod Linux-LKM_SysInterceptor
```

---

## 5. Technical Risks & Memory Volatility Analysis
Operating inside Supervisor Space (Ring 0) removes user-space memory protection boundaries, introducing severe hardware and software stability risks:

[System Memory Space]

```text
+-------------------------------------------------------------+

| Kernel Memory Space (Ring 0)                                |
|   +------------------+     Pointer Manipulation             |
|   | sys_call_table   |-----------------------+              |
|   +------------------+                       |              |
|            | (Original Call)                 v              |
|            v                       +--------------------+   |
|     [ sys_mkdir ]                  | Hooked Subsystem   |   |
|                                    | (Memory Resident)  |   |
|                                    +--------------------+   |
|                                              |              |
|                                              v              |
|                                      Unallocated Fault      |
|                                      (If Unloaded Wrong)    |
|                                              |              |
|                                              v              |
|                                    ====================     |
|                                    CRITICAL KERNEL PANIC    |
|                                    ====================     |
+-------------------------------------------------------------+
```

* **Dangling Pointer Instability (Kernel Panic):** If the module text segment is de-allocated or forced out of kernel space without properly clean-executing the `Linux_LKM_SysInterceptor_exit` destructor vector, the target index inside `sys_call_table` remains bound to a dead memory address. The subsequent invocation of that system call index by any host process will instantly trigger an unrecoverable Page Fault, inducing an immediate system collapse (Kernel Panic).
* **Multicore Race Conditions:** Simultaneous state mutation of hardware control registers (`CR0`) across separate physical CPU cores during pointer swap operations can induce core out-of-sync states or split-lock synchronization faults.
* **System Call Table Invalidation:** Modern enterprise kernels employ Kernel Page-Table Isolation (KPTI) and Control Flow Integrity (CFI) parameters. Unauthorized overrides of memory pages without aligning with native internal kernel locking mechanisms can result in hardware detection and automatic host protection reboots.

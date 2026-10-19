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
    char buf[16];
    if (copy_from_user(buf, pathname, sizeof(buf) - 1) == 0) {
        buf[sizeof(buf) - 1] = '\0';
        if (strcmp(buf, "block_dir") == 0) {
            return -EACCES;
        }
    }
    return original_mkdir(pathname, mode);
}

static int __init boutaba_kernel_init(void) {
    sys_call_table_ptr = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table_ptr) return -EINVAL;

    original_mkdir = (void *)sys_call_table_ptr[__NR_mkdir];

    write_cr0(read_cr0() & ~0x00010000);
    sys_call_table_ptr[__NR_mkdir] = (unsigned long)boutaba_hooked_mkdir;
    write_cr0(read_cr0() | 0x00010000);

    return 0;
}

static void __exit boutaba_kernel_exit(void) {
    if (sys_call_table_ptr && original_mkdir) {
        write_cr0(read_cr0() & ~0x00010000);
        sys_call_table_ptr[__NR_mkdir] = (unsigned long)original_mkdir;
        write_cr0(read_cr0() | 0x00010000);
    }
}

module_init(boutaba_kernel_init);
module_exit(boutaba_kernel_exit);

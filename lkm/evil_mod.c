/*
 * Example linux kernel module to hijack a syscall
 *
 * Big thanks to this guy for having readable code that finds the syscall
 * table:
 * https://github.com/ne2der/ASyScallHookFrame/blob/master/hook_syscalltable/kernel_hook.c
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>

/* printf, kindof */
#define printf(...) printk(KERN_EMERG __VA_ARGS__)

static int __init evil_mod_init (void);
static void __exit evil_mod_exit (void);
static void** find_sys_call_table (void);
static void* replace_syscall(void**, int, void*);
ssize_t evil_sys_write(int, const void*, size_t);

module_init(evil_mod_init);
module_exit(evil_mod_exit);

MODULE_LICENSE("GPL");

void **sys_call_table;
void *old_sys_write;

/* Init function */
static int __init evil_mod_init (void)
{
	/* Find and save the address of the syscall table */
	sys_call_table = find_sys_call_table();
	printf("syscall table: %p\n", sys_call_table);
	if (!sys_call_table) {
		/* Boo */
		printf("couldn't find syscall table\n");

		return 1;
	} else {
		/* Yay */

		/* Replace sys_write with evil sys_write*/
		old_sys_write = replace_syscall(sys_call_table, __NR_write, evil_sys_write);

		printf("replaced sys_write (%p) with evil_sys_write" \
			       " (%p)\n", old_sys_write, evil_sys_write);

		/* Disable write for syscall table */
		write_cr0(read_cr0() | 0x10000);

		return 0;
	}
}

/* Exit function */
static void __exit evil_mod_exit (void)
{
	/* If we found the syscall table */
	if (sys_call_table) {
		/* Restore old syscalls */
		replace_syscall(sys_call_table, __NR_write, old_sys_write);

		printf("restored sys_write\n");
	}

	printf("Bye!\n");
}

/* Finds syscall table or bust */
static void** find_sys_call_table (void)
{
	void **p;

	/* Search for syscall table by checking for address of sys_close */
	for (p = (void*) PAGE_OFFSET; (void*) p < (void*) ULLONG_MAX; p++) {
		if (p[__NR_close] == sys_close)
			/* Found it*/
			return p;
	}

	/* Did not find it */
	return NULL;
}

/* Replace a syscall */
static void* replace_syscall(void **table, int number, void *new) {
	void *ret;

	/* Enable write for syscall table */
	write_cr0(read_cr0() & (~0x10000));

	/* Replace syscall */
	ret = xchg(&table[number], new);

	/* Disable write for syscall table */
	write_cr0(read_cr0() | 0x10000);

	return ret;
}

/* "evil" sys_write function */
ssize_t evil_sys_write(int fd, const void *buf, size_t count) {
	/* TODO: evil stuff */

	/* Oh do I love C! */
	return ((ssize_t (*)(int, const void*, size_t))old_sys_write)(fd, buf, count);
}

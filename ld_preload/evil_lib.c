#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

typedef int (*printf_t)(const char *, ...);

/* Function to hijack printf with */
int printf (const char *format, ...)
{
	printf_t old_printf = (printf_t)dlsym(RTLD_NEXT, "printf");

	(void) format;

	return old_printf("You gots haxed!\n");
}

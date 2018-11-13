#include <stdio.h>

int main (int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s [string to print]\n", argv[0]);
		return 0;
	}

	/* Print user-supplied string */
	printf("Your string: %s\n", argv[1]);

	/*
	 * This is intersting, got optimized to a puts() because we're trying
	 * to print "string\n":
	 * https://github.com/gcc-mirror/gcc/blob/master/gcc/gimple-fold.c#L3523
	 *
	 * printf("%s\n", argv[1]);
	 */

	return 0;
}

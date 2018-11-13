/*
 * daemon.c
 *
 * An example of how to create a daemon in Linux.
 */

#include <stdio.h>

/* setsid, chdir, sysconf, close, sleep */
#include <unistd.h>

/* umask, open */
#include <sys/types.h>
#include <sys/stat.h>
/* open */
#include <fcntl.h>

/* errno */
#include <errno.h>

int main (void)
{
	int twice = 0;
	pid_t pid;
	int i;
	int maxfds;

	/*
	 * Fork twice, calling setsid() after the first fork
	 */
	while (!twice) {
		pid = fork();

		/* Error */
		if (pid == -1) {
			perror("fork");
			return 1;
		}

		/* Parent */
		if (pid > 0) {
			_exit(0);
		}

		/* Child */

		/*
		 * Become the process group leader. The call to setsid() will
		 * only fail if we are already the group leader, so checking
		 * the return value isn't necessary.
		 */
		if (!twice++)
			setsid();
	}

	/*
	 * Set the file creation permission mask to none.  The call to umask()
	 * returns the old umask and never fails, so we don't need to check it.
	 */
	umask(0);

	/*
	 * Change our working directory to root
	 */
	if (chdir("/") == -1) {
		perror("chdir");
		return 1;
	}

	/*
	 * Get the max number of file descriptors
	 */
	maxfds = sysconf(_SC_OPEN_MAX);
	if (maxfds == -1) {
		perror("sysconf");
		return 1;
	}

	/*
	 * Attempt to close every possible file descriptor
	 */
	for (i = 0; i < maxfds; i++) {
		if (close(i) < 0) {
			switch (errno) {
			case EBADF:
				/* Bad file descriptor, don't care */
				break;
			case EINTR:
				/* Interrupted by signal, try again */
				i--;
				break;
			case EIO:
				/* I/O error */
				perror("close");
				return 1;
			}
		}
	}

	/*
	 * Open stdin
	 */
	if (open("/dev/null", O_RDONLY) == -1) {
		perror("open");
		return 1;
	}

	/*
	 * Open stdout
	 */
	if (open("/dev/null", O_WRONLY) == -1) {
		perror("open");
		return 1;
	}

	/*
	 * Open stderr
	 */
	if (open("/dev/null", O_RDWR) == -1) {
		perror("open");
		return 1;
	}

	/*
	 * Go do daemon stuff (make lock file, open logs, catch signals, etc.)
	 */
	sleep(300);

	return 0;
}

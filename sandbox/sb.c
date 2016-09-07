#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "sb.h"

static int entry = 1;
static int access_vio = 0;

#define STR_BUF 1024
struct sandbox {
	pid_t child;
	const char *progname;
};

union _data {
	long val;
	char chars[8];
}data;

struct sandb_syscall {
	int syscall;
	void (*callback)(pid_t pid, struct user_regs_struct *regs, gl_array * ga);
};

void fetchdata(pid_t child, long addr, char *str, int len)
{
	char *laddr = str;
	int index = 0, count=0;
	int long_size = sizeof(long);
	count = len / long_size;
	while(index < count) {
		data.val = ptrace(PTRACE_PEEKDATA,
				child, addr + index * 8,
				NULL);
		memcpy(laddr, data.chars, long_size);
		++index;
		laddr += long_size;
		if (strlen(data.chars) < 8) {
			count = 0; /* No need to fetch remaining bytes */
			break;
		}
	}
	/* Fetch the remaining bytes */
	count = len % long_size;
	if(count != 0) {
		data.val = ptrace(PTRACE_PEEKDATA,
				child, addr + index * 8,
				NULL);
		memcpy(laddr, data.chars, count);
	}
	str[len] = '\0'; /* NULL terminate it */
}

void unlink_check(pid_t pid, struct user_regs_struct *regs, gl_array *ga) {
	char * str = malloc (STR_BUF * sizeof(char));
	int perms = 0;
	int unlinkat = (regs->orig_rax == 263);

	int dirfd = 0;
	if (entry) {
		entry = 0;
		if (unlinkat)
			fetchdata(pid, regs->rsi, str, STR_BUF);
		else
			fetchdata(pid, regs->rdi, str, STR_BUF);
		char * dirc2 = strdup(str);
		char * dirc = dirname(dirc2);
		if (unlinkat)
			dirfd = regs->rdi;
		/* Check write permissions to the directory containing pathname*/
		if((perms = get_perm(dirc, ga)) != -1) {
			if (perms != 10 && perms != 11 && perms != 110 && perms != 111) {
				if (unlinkat)  {
					if (dirfd == AT_FDCWD){
						access_vio = 1;
						goto unlink_eaccess;
					}
				} else {
					access_vio = 1;
					goto unlink_eaccess;
				}
			}
		}
	} else {
		entry = 1;
		if (access_vio) {
			regs->rax = -EACCES;
			if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
				err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SETREGS:");
			access_vio = 0;

		}

	}
	free(str);
	return;

unlink_eaccess:
	regs->rax = -EACCES;
	if (unlinkat)
		regs->rsi = NULL;
	else
		regs->rdi = NULL;
	printf("unlink eacess\n");
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SETREGS:");
}


void rename_check(pid_t pid, struct user_regs_struct *regs, gl_array *ga) {
	char * old = malloc (STR_BUF * sizeof(char));
	char * new = malloc (STR_BUF * sizeof(char));

	int perms = 0;


	if (entry) {
		entry = 0;
		fetchdata(pid, regs->rdi, old, STR_BUF);
		fetchdata(pid, regs->rsi, new, STR_BUF);
		char * dirc2 = strdup(new);
		char * dirc = dirname(dirc2);

		/*check if destination directory has write and execute perms*/
       if((perms = get_perm(dirc, ga)) != -1) {
    	   if ((perms != 011) && (perms != 111)) {
    		   access_vio = 1;
    		   goto rename_eaccess;
    	   }
       }
	} else {
		entry = 1;
		if (access_vio) {
			regs->rax = -EACCES;
			if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
					err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SETREGS:");
			access_vio = 0;
		}
	}
	free(old);
	free(new);
	return;

rename_eaccess:
	regs->rax = -EACCES;
	regs->rdi = NULL;
	printf("rename eacess\n");
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SETREGS:");

}

void stat_check(pid_t pid, struct user_regs_struct *regs, gl_array *ga) {
	char * str = malloc (STR_BUF * sizeof(char));
	char *dirc, *dname;

	int perms = 0;
	int ancester_denied = 0;
	if (!entry) {
		entry = 1;
		fetchdata(pid, regs->rdi, str, STR_BUF);

		//printf("%s\n", str);
		char * path = realpath(str, NULL);
		dirc = strdup(path);
		dname = dirname(dirc);
		while (strcmp(dname, "/") != 0) {
			/*printf("dirname=%s\n", dname);*/
			if ((perms = get_perm(dname, ga)) != -1) {
				/*printf ("perms = %d\n", perms);*/
				if (!(perms & 1)) {
					ancester_denied = 1;
					goto stat_eaccess;
				}
			}
			path = dname;
			dirc = strdup(path);
			dname = dirname(dirc);
		}
		free(path);
	}
	else {
		entry = 0;
	}
	free(str);
	return;

stat_eaccess:
	regs->rax = -EACCES;
	printf("stat eacess\n");
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SETREGS:");

}
/*void exec_check(struct sandbox * sb, struct user_regs_struct *regs, glob_matches * ga) {
  char * str = malloc (STR_BUF * sizeof(char));
  fetchdata(sb->child, regs->rdi, str, STR_BUF);
  printf("filename %s\n", str);
  free(str);
  }*/
void write_check(pid_t pid, struct user_regs_struct *regs, gl_array * ga) {
	char * str;
	str = (char *)calloc((regs->rdx+1),sizeof(char));
	fetchdata(pid, regs->rsi, str,
			regs->rdx);

}

void open_check(pid_t pid, struct user_regs_struct *regs, gl_array * ga) {
	int openat = (regs->orig_rax == 257);
	int flags = ((openat) ? regs->rdx : regs->rsi);
	int dirfd = ((openat) ? regs->rdi : AT_FDCWD);
	int read_flag = 0, write_flag = 0, rd_wr = 0, exec_flag = 1;
	char *dirc, *dname;
	int perms = 0, open_allowed = 0;
	write_flag = flags & 1;
	read_flag = (flags & 1) == 0;
	rd_wr = flags & 02;
	char * str = malloc (STR_BUF * sizeof(char));
	if (entry) {
		entry = 0;
		if (openat) {
			fetchdata(pid, regs->rsi, str, STR_BUF); 
		} else {
			fetchdata(pid, regs->rdi, str, STR_BUF);
		}		
                /*printf("filename %s flags %d %d %d return %lld\n",
		str,read_flag, write_flag, rd_wr, regs->rax);*/
		char * path = realpath(str, NULL);
		if (errno != ENOENT) {
			dirc = strdup(path);
			dname = dirname(dirc);
		} else {
			dirc = strdup(str);
			dname = realpath(dirname(str), NULL);
			/*Even the directory doesnt exist*/
			if (dname == NULL) {
				regs->rax = -errno;
				return;
			}
		}
		while (strcmp(dname, "/") != 0) {
			/*printf("dirname=%s\n", dname);*/
			if ((perms = get_perm(dname, ga)) != -1) {
				/*printf ("perms = %d\n", perms);*/
				if (perms != 1 && perms != 11 && perms != 111 && perms != 101) {
					access_vio = 1;
					goto eaccess;
				}
			}
			path = dname;
			dirc = strdup(path);
			dname = dirname(dirc);
		}
		free(path);
		//struct stat path_stat;

		/*if(stat (str, &path_stat) < 0) {
					goto eaccess;
		}*/

		/* If it is here then its a success */
		/*Checking file perms now */
		if ((perms = get_perm(str, ga)) != -1) {
			switch (perms)
			{
			case 100:
				if (read_flag && !write_flag && !rd_wr) open_allowed = 1;
				break;
			case 10:
				if (!read_flag && write_flag && !rd_wr) open_allowed = 1;
				break;
			case 1:
				/*if (S_ISDIR(path_stat.st_mode)) {
					if (exec_flag && !write_flag) open_allowed = 1;
					break;
				}*/
				/*Not sure why we need this case*/
				printf("here\n");
				if (!read_flag && !write_flag && exec_flag) open_allowed = 1;
				break;
			case 110:
				/* Cant check for exec perms for a file in an open call*/
				if ((rd_wr || read_flag || write_flag)) open_allowed = 1;
				break;
			case 0:
				open_allowed = 0;
				break;
			case 101:
				if ((read_flag || exec_flag) && !rd_wr && !write_flag) open_allowed = 1;
				break;
			case 111:
				if (read_flag || write_flag || exec_flag || rd_wr) open_allowed = 1;
				break;
			case 11:
				if (!read_flag && (write_flag || exec_flag)) open_allowed = 1;
				break;
			default:
				open_allowed = 0;
			}
			if (!open_allowed) {
				access_vio = 1;
				goto eaccess;
			}
		}
	} else {
		entry = 1;
		if (access_vio) {		
			regs->rax = -EACCES;
			if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
				err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SETREGS:");
			access_vio = 0;
		}
	}
	free(str);
	return;

eaccess:
	if (str) {
		free(str);
		str = NULL;
	}
	regs->rax = -EACCES;
	if (openat) {
		regs->rsi = NULL;
	}
	else { 
		regs->rdi = NULL;
	}
	printf("open eacess\n");
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SETREGS:");

}

struct sandb_syscall sandb_syscalls[] = {
		{__NR_read,            NULL},
		{__NR_write,           write_check},
		{__NR_exit,            NULL},
		{__NR_brk,             NULL},
		{__NR_mmap,            NULL},
		{__NR_access,          NULL},
		{__NR_open,            open_check},
		{__NR_stat,            stat_check},
		{__NR_rename,          rename_check},
		{__NR_unlink,          unlink_check},
		{__NR_unlinkat,        unlink_check},
                {__NR_openat,          open_check},
		{__NR_fstat,           NULL},
		{__NR_close,           NULL},
		{__NR_mprotect,        NULL},
		{__NR_munmap,          NULL},
		{__NR_execve,          NULL},
		{__NR_arch_prctl,      NULL},
		{__NR_exit_group,      NULL},
		{__NR_getdents,        NULL},
};

void sandb_kill(pid_t pid, int status) {
	kill(pid, SIGKILL);
	wait(NULL);
	if (!WIFEXITED(status))
		exit(EXIT_FAILURE);
}

void sandb_handle_syscall(pid_t pid, gl_array * ga) {
	int i;
	struct user_regs_struct regs;

	if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

	for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
		if(regs.orig_rax == sandb_syscalls[i].syscall) {
			if(sandb_syscalls[i].callback != NULL)
				sandb_syscalls[i].callback(pid, &regs, ga);
			//printf ("Sys call numbers: %ld\n", regs.orig_rax);
			return;
		}
	}

	if(regs.orig_rax == -1) {
		printf("[SANDBOX] Segfault ?! KILLING !!!\n");
	} /*else {
		//printf ("Sys call numbers: %ld\n", regs.orig_rax);
		//printf("[SANDBOX] Trying to use devil syscall (%llu) ?!? KILLING !!!\n", regs.orig_rax);
	}*/
	//sandb_kill(sandb);
}

void sandb_init(struct sandbox *sandb, int argc, char **argv, gl_array* ga) {
	pid_t pid;

	pid = fork();

	if(pid == -1)
		err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

	if(pid == 0) {

		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
			err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");

		if(execve(argv[0], argv, NULL) < 0)
			err(EXIT_FAILURE, "[SANDBOX] Failed to execve:");

	} else {
		int status;
		int child_stopped = 0;
		int option_set = 0;
		sandb->child = pid;
		sandb->progname = argv[0];

		while ((pid = waitpid(-1, &status, 0)) != -1) {
			if(WIFSTOPPED(status)) {
				/*if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
					child_stopped = 1;
					ptrace(PTRACE_GETEVENTMSG, pid, 0, &long_var);  Should be the PID of the new process
					if(ptrace(PTRACE_SYSCALL, long_var, NULL, NULL) < 0) {  Restart it right away
						if(errno == ESRCH) {
							waitpid(pid, &status, __WALL | WNOHANG);
							sandb_kill(pid, status);
						} else {
							err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
						}
					}
					wait(NULL);
					printf("New process %ld", long_var);
					sandb_handle_syscall(long_var, ga);
				}*/
				if (!option_set) {
					if (ptrace(PTRACE_SETOPTIONS, pid, 0,  PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK) < 0) {
						if(errno == ESRCH) {
							waitpid(pid, &status, __WALL | WNOHANG);
							sandb_kill(pid, status);
						}
					} else {
						option_set = 1;
					}
				}

				if (!child_stopped)
					sandb_handle_syscall(pid, ga);
				if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
					if(errno == ESRCH) {
						waitpid(pid, &status, __WALL | WNOHANG);
						sandb_kill(pid, status);
					} else {
						err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
					}
				}
			}
		}
	}
}

/*void sandb_run(pid_t * pidp, glob_matches * ga) {
  int status;
  pid_t pid;

  while{
  ptrace
  }
  if(ptrace(PTRACE_SYSCALL, *pidp, NULL, NULL) < 0) {
  if(errno == ESRCH) {
  waitpid(pid, &status, __WALL | WNOHANG);
  sandb_kill(pid, status);
  } else {
  err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
  }
  }

  pid = waitpid(-1, &status, __WALL);

  if (pid == -1 && errno == ECHILD)
  exit(EXIT_SUCCESS);

  if(WIFSTOPPED(status) ) {
  if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
  New process will begin with a SIGSTOP, so wait for SIGCHILD
  pid = waitpid(-1, &status, __WALL);
  if (WIFSTOPPED(status)) {
  if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
  if(errno == ESRCH) {
  waitpid(pid, &status, __WALL | WNOHANG);
  sandb_kill(pid, status);
  } else {
  err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
  }
  }
  }
  }
  if (ptrace(PTRACE_SETOPTIONS, pid, 0,  PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK) < 0) {
  if(errno == ESRCH) {
  waitpid(pid, &status, __WALL | WNOHANG);
  sandb_kill(pid, status);
  }
  }
  sandb_handle_syscall(pid, ga);
  }
  }*/

int main(int argc, char **argv) {
	struct sandbox sandb;
	gl_array * glob_array = NULL;
	int numlines = 0;

	if(argc < 2) {
		errx(EXIT_FAILURE, "[SANDBOX] Usage : %s [-c configfile] <elf> [<arg1...>]", argv[0]);
	}

	//printf ("%s %s %s %s %s\n", argv[0], argv[1], argv[2], argv[3], argv[4]);
	if ((strcmp(argv[1], "-c") == 0)) {
		if (argv[2]) {
			FILE * config_fd;
			config_fd = fopen(argv[2], "r");
			if (config_fd == NULL) {
				perror("Unable to open file\n");
			}
			parse_file(config_fd, &glob_array, &numlines);
			fclose(config_fd);

			sandb_init(&sandb, argc-3, argv+3, glob_array);

		}
	} else {
		FILE * fendrc;
		fendrc = fopen("./.fendrc", "r");
		if (fendrc == NULL) {
			fendrc = fopen("~/.fendrc", "r");
			if (fendrc == NULL) {
				errx(EXIT_FAILURE, "Must provide a config file.");
			}
		}
		parse_file(fendrc, &glob_array, &numlines);
		fclose(fendrc);

		sandb_init(&sandb, argc-1, argv+1, glob_array);
	}


	/*for (;;) {
	  sandb_run(sandb.child, glob_array);
	  }
	 */
	return EXIT_SUCCESS;
}

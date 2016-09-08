#include "sb.h"

static int entry = 1;
static int access_vio = 0;

#define STR_BUF 1024
struct fend_s {
	pid_t child;
	const char *cmd;
};

union _data {
	long val;
	char chars[8];
}data;

union _sock_data {
	long val;
        struct sockaddr sa;
}sock_data;

struct fend_syscall {
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

void fetchsockdata(pid_t child, long addr, struct sockaddr_un *str, int len)
{
	void *laddr = (void *) str;
	int index = 0, count=0;
	int long_size = sizeof(long);
        long val = 0;
	count = len / long_size;
	while(index < count) {
		val = ptrace(PTRACE_PEEKDATA,
				child, addr + index * 8,
				NULL);
		memcpy(laddr, &val, long_size);
		++index;
		laddr += long_size;
	}
	/* Fetch the remaining bytes */
	count = len % long_size;
	if(count != 0) {
		val = ptrace(PTRACE_PEEKDATA,
				child, addr + index * 8,
				NULL);
		memcpy(laddr, &val, count);
	}
}

void bind_check(pid_t pid, struct user_regs_struct *regs, gl_array *ga) {
	struct sockaddr_un sa;
	/*both connect and bind call will run this*/
	int bind_call = (regs->orig_rax == __NR_bind);	
	int addrlen = regs->rdx;
	long addr = regs->rsi;
        int perms = 0;
          char * dirc2, *dirc, *dname;
	if (entry) {
		entry = 0;

		fetchsockdata(pid, addr, &sa, addrlen);
               /*Only valid of UNIX sockets*/
		if (sa.sun_family != AF_UNIX) return;
                char * path;
		if ((path = realpath(sa.sun_path, NULL)) != NULL) { 
			dirc = strdup(path);
			dname = dirname(dirc);
		} else {
			/* Create operation */
			/*check write and exec perms of parent*/
			dirc = strdup(sa.sun_path);
			dname = realpath(dirname(dirc), NULL);
			if ((perms = get_perm(dname, ga)) != -1) {
				if (perms != 10 && perms != 11 && perms != 110 && perms != 111) {
					access_vio = 1;
					goto bind_eaccess;
				}
			}	

		}
		/*Check if the address has any of its ancestors denied. Common for bind and connect*/
		while (strcmp(dname, "/") != 0) {
			if((perms = get_perm(dirc, ga)) != -1) {
				if (perms != 1 && perms != 11 && perms != 101 && perms != 111) {
					access_vio = 1;
					goto bind_eaccess;

				}
				path = dname;
				dirc = strdup(path);
				dname = dirname(dirc);

			}
		}
		free(path);

		/*Check write perms on socket file for Connect call */
		if (!bind_call) {
			if ((perms = get_perm(sa.sun_path, ga)) != -1) {
				if (perms != 10 && perms != 11 && perms != 110 && perms != 111) {
					access_vio = 1;
					goto bind_eaccess;
				}

			} 
		}

	} else {
		entry = 1;
		if (access_vio = 1) {
			regs->rax = -EACCES;
			if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
				err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");
			access_vio = 0;

		}
	}
	return;

bind_eaccess:
	regs->rax = -EACCES;
	regs->rsi = 0;
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");

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
				err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");
			access_vio = 0;

		}

	}
	free(str);
	return;

unlink_eaccess:
	regs->rax = -EACCES;
	if (unlinkat)
		regs->rsi = 0;
	else
		regs->rdi = 0;
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");
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
			if ((perms != 11) && (perms != 111)) {
				access_vio = 1;
				goto rename_eaccess;
			}
		}
		if((perms = get_perm(dirname(strdup(new)), ga)) != -1) {
			if ((perms != 11) && (perms != 111)) {
				access_vio = 1;
				goto rename_eaccess;
			}
		}
	} else {
		entry = 1;
		if (access_vio) {
			regs->rax = -EACCES;
			if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
				err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");
			access_vio = 0;
		}
	}
	free(old);
	free(new);
	return;

rename_eaccess:
	regs->rax = -EACCES;
	regs->rdi = 0;
	regs->rsi = 0;
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");

}
void mkdir_check(pid_t pid, struct user_regs_struct *regs, gl_array *ga) {

	char * str = malloc (STR_BUF * sizeof(char));
	char *dirc, *dname;
        int mkdir_call = (regs->orig_rax == __NR_mkdir);

	int perms = 0;
	if (!entry) {
		entry = 1;
		fetchdata(pid, regs->rdi, str, STR_BUF);

		char * path = realpath(str, NULL);
               if (mkdir_call != 1 ) {  
		if (path == NULL) {
			dirc = strdup(str);
			dname = realpath(dirname(dirc), NULL);
			if ((perms = get_perm(dname, ga)) != -1) {
				if (perms != 10 && perms != 11 && perms != 110 && perms != 111) {
					access_vio = 1;
					goto mkdir_eaccess;
				}
			}
		} else {
			regs->rax = -errno;
			return;
		}
	       } else {
		       if (path != NULL) {
			       dirc = strdup(str);
			       dname = realpath(dirname(dirc), NULL);
			       if ((perms = get_perm(dname, ga)) != -1) {
				       if (perms != 10 && perms != 11 && perms != 110 && perms != 111) {
					       access_vio = 1;
					       goto mkdir_eaccess;
				       }
			       }
		       } else {
			       regs->rax = -errno;
			       return;
		       }


	       }
		while (strcmp(dname, "/") != 0) {
			if ((perms = get_perm(dname, ga)) != -1) {
				if (!(perms & 1)) {
							goto mkdir_eaccess;
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

mkdir_eaccess:
	regs->rax = -EACCES;
        regs->rdi = 0;
       /* Seems like the directory is always created. Insert hack*/
        if  (mkdir_call == 1) rmdir(realpath(str, NULL));
        else mkdir(realpath(str, NULL), 0755);
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");

}

void stat_check(pid_t pid, struct user_regs_struct *regs, gl_array *ga) {
	char * str = malloc (STR_BUF * sizeof(char));
	char *dirc, *dname;
        int stat_call = (regs->orig_rax == __NR_stat);

	int perms = 0;
	if (!entry) {
		entry = 1;
                if (stat_call)
		fetchdata(pid, regs->rdi, str, STR_BUF);
                else 
		fetchdata(pid, regs->rsi, str, STR_BUF);

		char * path = realpath(str, NULL);
                
		if (path != NULL) {
			dirc = strdup(path);
			dname = dirname(dirc);
		} else {
			regs->rax = -errno;
			return;
		}
		while (strcmp(dname, "/") != 0) {
			if ((perms = get_perm(dname, ga)) != -1) {
				if (!(perms & 1)) {
					if (stat_call) {
						goto stat_eaccess;
					}
					else {
						if (regs->rdi == AT_FDCWD) { 
							goto stat_eaccess;
						}
					}
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
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");

}
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
		char * path = realpath(str, NULL);
		/* It is possible it is a file create */
		if (path != NULL) {
			dirc = strdup(path);
			dname = dirname(dirc);
		} else {
			if(write_flag && (flags & 0100)) {
				/*Create operation*/

				/*check directory write perms*/
				dirc = strdup(str);
				dname = realpath(dirname(dirc),NULL);
				if ((perms = get_perm(dname, ga)) != -1) {
					if (perms != 10 && perms != 11 && perms != 110 && perms != 111) {
						access_vio = 1;
						goto eaccess;
					}
				}	
			} else {
				regs->rax = -errno;
				return;
			}
		}
		/* Check search permissions for the directories in the path*/
		while (strcmp(dname, "/") != 0) {
			if ((perms = get_perm(dname, ga)) != -1) {
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
				if (!read_flag && !write_flag && exec_flag) open_allowed = 1;
				break;
			case 110:
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
				err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");
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
		regs->rsi = 0;
	}
	else { 
		regs->rdi = 0;
	}
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
		err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SETREGS:");

}

struct fend_syscall fend_syscalls[] = {
		{__NR_read,            NULL},
		{__NR_write,           write_check},
		{__NR_access,          NULL},
		{__NR_open,            open_check},
		{__NR_stat,            stat_check},
		{__NR_rename,          rename_check},
		{__NR_unlink,          unlink_check},
		{__NR_unlinkat,        unlink_check},
                {__NR_openat,          open_check},
		{__NR_fstat,           NULL},
		{__NR_close,           NULL},
		{__NR_bind,            bind_check},
		{__NR_connect, 	       bind_check},
                {__NR_newfstatat,      stat_check},
                {__NR_mkdir,           mkdir_check},
                {__NR_rmdir,           mkdir_check},
		{__NR_mprotect,        NULL},
};

void fend_kill(pid_t pid, int status) {
	kill(pid, SIGKILL);
	wait(NULL);
	if (!WIFEXITED(status))
		exit(EXIT_FAILURE);
}

void fend_handle_syscall(pid_t pid, gl_array * ga) {
	int i;
	struct user_regs_struct regs;

	if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(EXIT_FAILURE, "[FEND] Failed to PTRACE_GETREGS:");

	for(i = 0; i < sizeof(fend_syscalls)/sizeof(*fend_syscalls); i++) {
		if(regs.orig_rax == fend_syscalls[i].syscall) {
			if(fend_syscalls[i].callback != NULL)
				fend_syscalls[i].callback(pid, &regs, ga);
			return;
		}
	}

	if(regs.orig_rax == -1) {
		printf("[FEND] Segfault ?! KILLING !!!\n");
	} 
}

void fend_init(struct fend_s *fend, int argc, char **argv, gl_array* ga) {
	pid_t pid;

	pid = fork();

	if(pid == -1)
		err(EXIT_FAILURE, "[FEND] Error on fork:");

	if(pid == 0) {

		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
			err(EXIT_FAILURE, "[FEND] Failed to PTRACE_TRACEME:");

		if(execvp(argv[0], argv) < 0)
			err(EXIT_FAILURE, "[FEND] Failed to execve:");

	} else {
		int status;
		int child_stopped = 0;
		int option_set = 0;
		fend->child = pid;
		fend->cmd = argv[0];

		while ((pid = waitpid(-1, &status, 0)) != -1) {
			if(WIFSTOPPED(status)) {
				if (!option_set) {
					if (ptrace(PTRACE_SETOPTIONS, pid, 0,  PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK) < 0) {
						if(errno == ESRCH) {
							waitpid(pid, &status, __WALL | WNOHANG);
							fend_kill(pid, status);
						}
					} else {
						option_set = 1;
					}
				}

				if (!child_stopped)
					fend_handle_syscall(pid, ga);
				if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
					if(errno == ESRCH) {
						waitpid(pid, &status, __WALL | WNOHANG);
						fend_kill(pid, status);
					} else {
						err(EXIT_FAILURE, "[FEND] Failed to PTRACE_SYSCALL:");
					}
				}
			}
		}
	}
}

int main(int argc, char **argv) {
	struct fend_s fend;
	gl_array * glob_array = NULL;
	int numlines = 0;

	if(argc < 2) {
		errx(EXIT_FAILURE, "[FEND] Usage : %s [-c configfile] <elf> [<arg1...>]", argv[0]);
	}

	if ((strcmp(argv[1], "-c") == 0)) {
		if (argv[2]) {
			FILE * config_fd;
			config_fd = fopen(argv[2], "r");
			if (config_fd == NULL) {
				perror("Unable to open file\n");
			}
			parse_file(config_fd, &glob_array, &numlines);
			fclose(config_fd);

			fend_init(&fend, argc-3, argv+3, glob_array);

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

		fend_init(&fend, argc-1, argv+1, glob_array);
	}


	return EXIT_SUCCESS;
}

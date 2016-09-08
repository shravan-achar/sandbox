#ifndef SB_H
#define SB_H

#include <glob.h>
#include <libgen.h>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>


typedef struct {
	char pattern[128];
	int perms;
}glob_matches;

typedef glob_matches * gl_array;

int get_perm(const char * fn, gl_array * glob_arr);

void parse_file(FILE * fd, gl_array ** glob_array, int * number_of_lines);

#endif

#ifndef SB_H
#define SB_H

#include <glob.h>
#include <libgen.h>


typedef struct {
	char pattern[64];
	int perms;
	glob_t * pglob;
}glob_matches;

typedef glob_matches * gl_array;

int get_perm(const char * fn, gl_array * glob_arr);

void parse_file(FILE * fd, gl_array ** glob_array, int * number_of_lines);

#endif

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
#include <glob.h>
#include <limits.h>
#include "sb.h"


int lines;
glob_t * parse_pattern(const char * pattern) {

	glob_t * pglob;
	pglob = malloc(sizeof(glob_t));
	/*int rc = 0;*/
	/* TODO: Error function is NULL for now*/
	/*rc = */glob(pattern, GLOB_TILDE, NULL, pglob);

	/*if (rc == GLOB_NOMATCH)
		printf ("Found No match for pattern %s\n",pattern);*/

	return pglob;

}
void getlines (FILE * fd, int * count) {
	int ch;
	fseek(fd, 0, SEEK_SET);
	do
		{
		    ch = fgetc(fd);
		    if(ch == '\n')
		    	(*count)++;
		} while (ch != EOF);

		if(ch != '\n') {
			(*count)++;
		}
}

void parse_file(FILE * fd, gl_array ** Glob_array, int * number_of_lines)
{

	getlines(fd, number_of_lines);

	int size = sizeof(glob_matches);


	gl_array * gl_a = malloc(*number_of_lines * sizeof(gl_array));
    int	index = 0, perms = 0;
	while (index < (*number_of_lines)) {
		gl_a[index] = malloc(size);
		index++;
	}
	*Glob_array = gl_a;
 index = 0;
	char pattern[64];
	memset(pattern, 0, 64);
	fseek(fd, 0, SEEK_SET);
	while (index < (*number_of_lines)) {

		    fscanf(fd, "%d %s", &perms, pattern);
			memcpy(gl_a[index]->pattern, pattern, 64);
			gl_a[index]->perms = perms;
			gl_a[index]->pglob = parse_pattern(pattern);

		index++;
	}
	lines = *(number_of_lines);
}
int get_match(int index, const char *fn, gl_array * glob_arr){
		int j = 0;
                char * path_buf = malloc(PATH_MAX * sizeof(char));
		glob_t * pglob = glob_arr[index]->pglob;

		for (j = 0; j < pglob->gl_pathc; j++) {
			if(strcmp(fn, (char *)realpath(pglob->gl_pathv[j], path_buf)) == 0) {
                                free(path_buf);
				return j;
			}
		}
		return -1;
}

int get_perm(const char * fn, gl_array * glob_arr) {

	int index = 0;
	int count = -1;
	int str_pos = 0;
	char * path_buf = malloc(PATH_MAX * sizeof(char));
	char * abs_path = NULL;
	abs_path = realpath(fn, path_buf);
	for (index = 0; index < lines; index++) {
		if ((str_pos = get_match(index, abs_path, glob_arr)) != -1) {
			count = index;
			/*printf("{DEBUG}: Matched string %s\n", glob_arr[index]->pglob->gl_pathv[str_pos]);*/
		}
	}
	if (count > -1) {
                free(path_buf);
		return (glob_arr[count]->perms);
	} else {
		free(path_buf);
		return -1;
	}

}





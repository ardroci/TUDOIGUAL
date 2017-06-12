#include "diff.h"
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <mba/diff.h>
#include <mba/msgno.h>
#include <sys/stat.h>
#include <sys/mman.h>

static inline int max(int a, int b) { return a < b ? b : a; }

int print_diff(char *buffer, const char *filename, const char *a, int a_size,
		const char *b, int b_size);

void unmapfile(char *data, int size)
{
	munmap(data, size);
}

void *mapfd(int fd, int *size)
{
	struct stat st;

	if(fstat(fd, &st) == -1) return NULL;

	void *ret = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if(ret == MAP_FAILED) return NULL;

	*size = st.st_size;

	return ret;
}

void *mapfile(int dirfd, const char *filename, int *size)
{
	int fd;

	if((fd = openat(dirfd, filename, O_RDONLY | O_CREAT), 0666) == -1)
	{
		return NULL;
	}
	void *ret = mapfd(fd, size);

	close(fd);

	return ret;
}

int alternative(int dirfd, const char *filename_a, int flags, mode_t mode)
{
	char filename_b[256];
	sprintf(filename_b, ".%s", filename_a);
	return openat(dirfd, filename_b, flags, mode);
}

/* void backup(int dirfd, const char *filename_a) */
/* { */
/* 	int size = 0; */
/* 	int b_fd = alternative(dirfd, filename_a, O_WRONLY | O_CREAT, 0666); */
/* 	char *data = mapfile(dirfd, filename_a, &size); */
/* 	write(b_fd, data, size); */
/* 	unmapfile(data, size); */
/* } */

char *pdiff(int dirfd, const char *filename, int *size)
{
	int a_size = 0;
	int a_fd = openat(dirfd, filename, O_RDONLY);
	char *a = mapfd(a_fd, &a_size);

	int b_size = 0;
	int b_fd = alternative(dirfd, filename, O_RDONLY | O_CREAT, 0666);
	char *b = mapfd(b_fd, &b_size);

	char *message = malloc(max(a_size, b_size) + 32);

	*size = print_diff(message, filename, a, a_size, b, b_size);

	if(*size)
	{
		close(b_fd);
		b_fd = alternative(dirfd, filename, O_WRONLY | O_TRUNC, 0);
		write(b_fd, a, a_size);
	}

	unmapfile(a, a_size);
	unmapfile(b, b_size);

	close(a_fd);
	close(b_fd);
	return message;
}

int print_diff(char *buffer, const char *filename, const char *a, int a_size,
		const char *b, int b_size)
{
	if(a_size == 0) return 0;

	int size = 0;
	int line;
	int changes_size, i, changes = 0;
	struct varray *ses = varray_new(sizeof(struct diff_edit), NULL);

	if ((line = diff(b, 0, b_size, a, 0, a_size, NULL, NULL, NULL, 0,
					ses, &changes_size, NULL)) == -1)
	{
		varray_deinit(ses);
		return 0;
	}

	if(!line)
	{
		varray_deinit(ses);
		return 0;
	}
	char *end = buffer;

	/* STORE FILE NAME */
	/* int name_size = strlen(filename) + 1; */
	/* memcpy(end, &name_size, sizeof name_size); end += sizeof name_size; */
	/* memcpy(end, filename, name_size); */
	/* end += name_size; */

	end += sizeof changes; /* Reserve space for number of changes */

	/* STORE CHANGES */
	for(i = 0; i < changes_size; i++)
	{
		struct diff_edit *e = varray_get(ses, i);

		/* if(e->op == DIFF_INSERT || e->op == DIFF_DELETE) */
		{
			if(e->len == 0) continue;
			memcpy(end, &e->off, sizeof e->off); end += sizeof e->off;
			memcpy(end, &e->len, sizeof e->len); end += sizeof e->len;
			if(e->op == DIFF_MATCH)
			{
				*end = '='; end++;
			}
			else if(e->op == DIFF_INSERT)
			{
				*end = '+'; end++;
				memcpy(end, a + e->off, e->len); end += e->len;
			}
			else
			{
				*end = '-'; end++;
			}
			changes++;
		}
	}
	varray_deinit(ses);
	*end = '\0';

	memcpy(buffer, &changes, sizeof changes);
	size = (int)(end - buffer);

	return size;
}

void apply_diff(int fd, char *a, int a_size, char *diff)
{
	char *end = diff;
	int changes;
	memcpy(&changes, end, sizeof changes); end += sizeof changes;
	int i;
	for(i = 0; i < changes; i++)
	{
		int len;
		int off;
		char op;
		memcpy(&off, end, sizeof off); end += sizeof off;
		memcpy(&len, end, sizeof len); end += sizeof len;
		memcpy(&op, end, sizeof op); end += sizeof op;
		/* printf("%c %d %d\n", op, off, len); */

		if(op == '=')
		{
			write(fd, a + off, len);
			printf("[33m%.*s[0m", len, a + off);
		}
		if(op == '+')
		{
			write(fd, end, len);
			printf("[32m%.*s[0m", len, end);
			end += len;
		}
		if(op == '-')
		{
			printf("[31m%.*s[0m", len, a + off);
		}
	}
	/* if(a_size) */
	/* { */
	/* 	write(fd, a, a_size); */
	/* 	printf("%.*s", a_size, a); */
	/* } */
	printf("\n");
}

void adiff(int dirfd, char *diff)
{
	int a_size = 0, b_size = 0;

	int name_size = 0;
	char *filename;

	/* GET FILENAME */
	memcpy(&name_size, diff, sizeof name_size); diff += sizeof name_size;
	filename = malloc(sizeof(*filename) * (name_size + 1));
	memcpy(filename, diff, name_size); diff += name_size;
	filename[name_size] = '\0';

	char *dir = strdup(filename);

	struct stat st;
	char *separator = strchr(dir, '/');

	if(separator)
	{
		*separator = '\0';
		if(fstatat(dirfd, dir, &st, 0) == -1)
		{
			mkdirat(dirfd, dir, S_IRWXU | S_IRWXG | S_IRWXO);
		}
		*separator = '/';
	}

	int a_fd = openat(dirfd, filename, O_RDONLY | O_CREAT, 0666);
	if(a_fd == -1) perror("Could not open 'a' file: ");
	char *a = mapfd(a_fd, &a_size);

	int b_fd = alternative(dirfd, filename, O_WRONLY | O_CREAT
			| O_TRUNC, 0666);
	if(b_fd == -1) perror("Could not open 'b' file: ");

	apply_diff(b_fd, a, a_size, diff);

	close(a_fd);
	close(b_fd);

	unmapfile(a, a_size);

	{
		a_fd = openat(dirfd, filename, O_WRONLY | O_TRUNC);
		b_fd = alternative(dirfd, filename, O_RDONLY, 0);
		char *b = mapfd(b_fd, &b_size);
		write(a_fd, b, b_size);
		unmapfile(b, b_size);
		close(a_fd);
		close(b_fd);
	}

	free(filename);
	free(dir);
}

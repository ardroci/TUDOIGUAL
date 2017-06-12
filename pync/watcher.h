#ifndef WATCHER_H
#define WATCHER_H

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stddef.h>
#include <mba/cfg.h>

typedef struct watcher_t watcher_t;

typedef struct
{
	char name[64];
	char dir[1024];
	int dirfd;

	pthread_t thread;
	int exit;
#ifdef __APPLE__
#elif __linux__
	int inotify_fd;
	int inotify_wd;
#endif

	watcher_t *watcher;
} repo_t;

typedef void (*modify_cb)(repo_t *repo, const char *buffer, int len,
		void *userptr);

typedef void (*add_cb)(const char *name, const char *dir, void *userptr);



typedef struct watcher_t
{
	modify_cb on_modify;
	add_cb on_add;
	void *userptr;
	repo_t **repos; size_t repos_size;
	int fifo_fd;
	int exit;
} watcher_t;

watcher_t *watcher_new(modify_cb on_modify, add_cb on_add, void *userptr);
void watcher_watch(watcher_t *self, const char *dir);
void watcher_run(watcher_t *self);
repo_t *watcher_repo(watcher_t *self, const char *repo_name);
void watcher_destroy(watcher_t *self);

#endif /* !WATCHER_H */

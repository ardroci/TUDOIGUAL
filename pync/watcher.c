#include "watcher.h"
#include "diff.h"
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>


#ifdef __APPLE__
#include <libfswatch/c/libfswatch.h>
#elif __linux__
#include <sys/inotify.h>

#define EVENT_SIZE		( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN	( 1024 * ( EVENT_SIZE + 16 ) )
#endif


const char *fifo = "/tmp/pync";

static repo_t *repo_new(const char *name, const char *dir, watcher_t *watcher);
static void repo_destroy(repo_t *self);
static void *repo_run(repo_t *self);
/* static void repo_wait(repo_t *self); */

static inline int min(int a, int b) { return a > b ? b : a; }

watcher_t *watcher_new(modify_cb on_modify, add_cb on_add, void *userptr)
{
	watcher_t *self = malloc(sizeof *self);
	self->on_modify = on_modify;
	self->on_add = on_add;
	self->userptr = userptr;
	self->repos = NULL;
	self->repos_size = 0;
	self->exit = 0;
	self->fifo_fd = -1;

#ifdef __APPLE__
	if(fsw_init_library() != FSW_OK)
	{
		printf("fswatcher failed to init!\n");
		fsw_last_error();
		exit(1);
	}
#endif

	return self;
}

void watcher_watch(watcher_t *self, const char *data)
{
	char *name = strdup(data);
	char *dir = strchr(name, ':') + 1;
	*(dir - 1) = '\0';

	if(self->on_add)
	{
		self->on_add(name, dir, self->userptr);
	}

	repo_t *repo = repo_new(name, dir, self);
	free(name);

	size_t i = self->repos_size++;
	self->repos = realloc(self->repos, self->repos_size * sizeof(repo_t*));
	self->repos[i] = repo;
}

void watcher_destroy(watcher_t *self)
{
	size_t i;
	self->exit = 1;
	for(i = 0; i < self->repos_size; ++i) repo_destroy(self->repos[i]);

	if(self->fifo_fd >= 0) close(self->fifo_fd);
	if(unlink(fifo) == -1) perror("Could not destroy fifo.\n");

	free(self->repos);
	free(self);
}

static void save_to_config(const char *data, int count)
{
	char buf[1024];
	FILE *f = fopen("./config", "a");
	sprintf(buf, "repo.%d = %s\n", count, data);
	fputs(buf, f);
	fclose(f);
}

void *_watcher_run(watcher_t *self)
{
	char cmd[5];
	char buf[512];

	if(mkfifo(fifo, 0777) < 0) perror("Can't create fifo.\n");

	while(!self->exit)
	{
		self->fifo_fd = open(fifo, O_RDONLY | O_CREAT);
		if(self->fifo_fd < 0) perror("Can't open fifo.\n");
		ssize_t len = read(self->fifo_fd, cmd, sizeof 4);
		if(len == -1) exit(0);
		if(len == 0) continue;
		if(self->exit) break;

		cmd[4] = '\0';
		if(!strncmp(cmd, "stop", sizeof cmd)) break;
		if(!strncmp(cmd, "add_", sizeof cmd))
		{
			len = read(self->fifo_fd, buf, sizeof buf);
			if(self->exit) break;
			if(len == -1) exit(0);

			watcher_watch(self, buf);

			save_to_config(buf, self->repos_size);
			buf[len] = '\0';
		}
		close(self->fifo_fd);
	}
	if(self->fifo_fd >= 0) close(self->fifo_fd);
	self->fifo_fd = -1;
	return NULL;
}

repo_t *watcher_repo(watcher_t *self, const char *repo_name)
{
	size_t i;
	for(i = 0; i < self->repos_size; i++)
	{
		repo_t *repo = self->repos[i];
		if(!strncmp(repo_name, repo->name, sizeof(repo->name)))
		{
			return repo;
		}
	}
	return NULL;
}


void watcher_run(watcher_t *self)
{
	pthread_t thr;
	if(pthread_create(&thr, NULL, (void*(*)(void*))_watcher_run, self))
	{
		perror("Error creating thread\n");
	}
}

static inline const char *strip_path(const char *dir, const char *file)
{
	const char *result;
	for(result = file; *dir && *result && *dir == *result; dir++, result++);
	if(result[0] == '/') result++;
	return result;
}

static inline int validate(const char *name)
{
	char base[1024];
	strcpy(base, name);
	char *n = basename(base);

	if(n[0] == '.') return 0;
	if(n[strlen(n) - 1] == '~') return 0;
	if(!strcmp(n, "4913")) return 0; /* vim temporary file */
	return 1;
}

void repo_modified(repo_t *self, const char *filename, const char *diff,
		int len)
{
	int file_len = strlen(filename);
	int final_len = len + sizeof(file_len) + file_len;
	char *final = malloc(final_len);
	char *end = final;
	memmove(end, &file_len, sizeof(file_len)); end += sizeof(file_len);
	memmove(end, filename, file_len); end += file_len;
	memmove(end, diff, len);

	if(self->watcher->on_modify)
	{
		self->watcher->on_modify(self, final, final_len,
				self->watcher->userptr);
	}

	free(final);
}

static void repo_check_file(repo_t *self, const char *filename)
{
	/* if(event->mask & IN_DELETE) {} */
	if(!validate(filename)) return;

	int len = 0;
	char *diff = pdiff(self->dirfd, filename, &len);

	if(len)
	{
		repo_modified(self, filename, diff, len);
	}
	if(diff) free(diff);

}

#ifdef __APPLE__
void fsnotify_cb(fsw_cevent const *const events, const unsigned int event_num,
		void *data)
{
	repo_t *self = data;
	unsigned int i, j;
	char filename[1024];
	for(i = 0; i < event_num; i++)
	{
		fsw_cevent const *e = &events[i];
		if(!validate(e->path)) continue;
		for(j = 0; j < e->flags_num; j++)
		{
			unsigned int flag = e->flags[j];
			if(flag & ((1 << 1) | (1 << 2) | (1 << 8)))
			{
				const char *relative = strip_path(self->dir, e->path);
				strcpy(filename, relative);

				repo_check_file(self->repo, filename);
				break;
			}
		}
	}

}
#endif

static void check_dir(repo_t *self, const char *name)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name)))
        return;
    if (!(entry = readdir(dir)))
        return;

    do {
        if (entry->d_type == DT_DIR) {
			if(!validate(entry->d_name)) continue;
            char path[1024];
            int len = snprintf(path, sizeof(path)-1, "%s/%s", name, entry->d_name);
            path[len] = '\0';
			printf("checking dir %s\n", entry->d_name);
            check_dir(self, path);
			printf("exiting dir %s\n", entry->d_name);
        }
        else
		{
			repo_check_file(self, entry->d_name);
		}
    } while ((entry = readdir(dir)));
    closedir(dir);
}

void repo_check_all_files(repo_t *self)
{
	check_dir(self, self->dir);
}

static void *repo_run(repo_t *self)
{
	repo_check_all_files(self);

#ifdef __APPLE__

	const FSW_HANDLE handle = fsw_init_session(system_default_monitor_type);
	if(FSW_INVALID_HANDLE != handle)
	{
		if(FSW_OK != fsw_add_path(handle, self->dir))
		{
			fsw_last_error();
		}

		if(FSW_OK != fsw_set_callback(handle, fsnotify_cb, self))
		{
			fsw_last_error();
		}

		fsw_set_allow_overflow(handle, 0);

		if(FSW_OK != fsw_start_monitor(handle))
		{
			fsw_last_error();	  
		}
	}

#elif __linux__
	ssize_t length;
	char buffer[EVENT_BUF_LEN];

	if((self->inotify_fd = inotify_init()) < 0)
	{
		perror("Failed to init inotify.\n");
	}

	self->inotify_wd = inotify_add_watch(self->inotify_fd, self->dir,
			IN_MOVED_TO | IN_CREATE |/* IN_DELETE |*/ IN_MODIFY);

	while(!self->exit)
	{
		int i = 0;
		length = read(self->inotify_fd, buffer, EVENT_BUF_LEN); 
		if(length == -1) break;

		while(i < length)
		{
			struct inotify_event *event = (struct inotify_event*)
				&buffer[i];
			if(event->len && event->name)
			{
				repo_check_file(self, event->name);
			}
			i += EVENT_SIZE + event->len;
		}
	}
#endif
	return NULL;
}

static repo_t *repo_new(const char *name, const char *dir, watcher_t *watcher)
{
	repo_t *self = malloc(sizeof *self);
	self->watcher = watcher;

	if(dir[0] != '/')
	{
		char cwd[1024];
		if(!getcwd(cwd, sizeof(cwd)))
		{
			exit(1);
		}
		snprintf(self->dir, sizeof self->dir, "%s/%s", cwd, dir);
	}
	else
	{
		strncpy(self->dir, dir, sizeof self->dir);
	}
	/* printf("Repo '%s' '%s'\n", name, self->dir); */


	strncpy(self->name, name, sizeof self->name);
	self->dirfd = open(dir, O_RDONLY | O_DIRECTORY);
	self->exit = 0;

	if(pthread_create(&self->thread, NULL, (void*(*)(void*))repo_run, self))
	{
		perror("Error creating thread\n");
	}

	return self;
}

/* static void repo_wait(repo_t *self) */
/* { */
/* 	pthread_join(self->thread, NULL); */
/* } */

static void repo_destroy(repo_t *self)
{
	if(!self->exit)
	{
		self->exit = 1;
#ifdef __APPLE__
#elif __linux__
		inotify_rm_watch(self->inotify_fd, self->inotify_wd);
		close(self->inotify_fd);
#endif
		pthread_cancel(self->thread);
	}

	close(self->dirfd);
	free(self);
}

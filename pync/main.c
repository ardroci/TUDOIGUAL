#include <mba/hexdump.h>

#include "watcher.h"
#include "diff.h"
#include <string.h>
#include <assert.h>
#include "onexit.h"
#include "client_module.h"
#include <sys/stat.h>

void on_receive(watcher_t *watcher, char *repo_name, char *diff, int len)
{
	printf("received: '%s'\n", repo_name);
	/* hexdump(stdout, diff, len, 16); */
	repo_t *repo = watcher_repo(watcher, repo_name);

	const char *clone_to = repo->dir;
	struct stat st;
	if(stat(clone_to, &st) == -1 && mkdir(clone_to, (S_IRWXU | S_IRWXG | S_IRWXO)))
	{
		perror("create dir failed: ");
	}
	int dirfd = open(clone_to, O_RDONLY | O_DIRECTORY);
	adiff(dirfd, diff);
	close(dirfd);
}

typedef struct
{
	watcher_t *watcher;
} data_t;

void on_modify(repo_t *repo, const char *diff, int len, data_t *data)
{
	/* printf("Change on repo '%s' file '%s'\n", repo->dir, filename); */
	/* hexdump(stdout, diff, len, 16); */

	server_new_diff(repo->name, diff, len);
}

#define MX 512
#define t(a) ((tchar*)(a))

void cleanup(data_t *data)
{
	watcher_destroy(data->watcher);
}

int main(int argc, char **argv)
{
	data_t data;

	int port, i;
	char addr[16];
	char name[16];
	char org[32];
	char repo[MX];

	struct cfg *cfg = cfg_new(stdlib_allocator);
	cfg_load(cfg, "./config");

	cfg_get_int(cfg, &port, 8000, t("port"));
	cfg_get_str(cfg, t(addr), sizeof addr, t("127.0.0.1"), t("addr"));
	cfg_get_str(cfg, t(name), sizeof name, t("alice"), t("name"));
	cfg_get_str(cfg, t(org), sizeof name, t("ubi"), t("org"));

	data.watcher = watcher_new((modify_cb)on_modify, (add_cb)server_listen_repo, &data);

	client_module_init(data.watcher, (receive_cb)on_receive);

	server_connect(addr, port, name, org);

	for(i = 1; cfg_vget_str(cfg, t(repo), MX, NULL, t("repo.%d"), i) >= 0; i++)
	{
		watcher_watch(data.watcher, repo);
		/* char c; */
		/* scanf("%c", &c); */
		/* server_listen_repo(repo); */
	}


	call_on_exit(cleanup, &data);

	watcher_run(data.watcher);

	client_module_run();

	watcher_destroy(data.watcher);

	cfg_del(cfg);

	printf("Ending.\n");
	client_module_finalize();

	return 0;
}

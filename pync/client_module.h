#ifndef CLIENT_MODULE_H
#define CLIENT_MODULE_H

typedef void (*receive_cb)(void *data, char *repo,
		char *diff, int len);

void client_module_init(void *data, receive_cb receive);

void client_module_run();

void server_connect(const char *ip, long port, const char *name,
		const char *org);

void server_new_diff(const char *repo, const char *diff, unsigned int len);

void server_req_key(const char *repo);

void server_listen_repo(const char *name, const char *dir);

void client_module_finalize();

#endif /* !CLIENT_MODULE_H */

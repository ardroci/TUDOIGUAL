#include "onexit.h"
#include <signal.h>
#include <stdlib.h>

static void *on_exit_cb;
static void *on_exit_data;
static int exited;

static void exit_cb(int s)
{
	if(!exited)
	{
		exited = 1;
		((void(*)(void*))on_exit_cb)(on_exit_data);
	}
	exit(0); 
}

void call_on_exit(void *cb, void *data)
{
	exited = 0;
	on_exit_cb = cb;
	on_exit_data = data;
	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = exit_cb;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
}

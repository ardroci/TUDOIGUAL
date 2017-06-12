#include "client_module.h"
#include <Python.h>
#include <pthread.h>

typedef struct
{
	PyObject *module;

	PyObject *server_connect;
	PyObject *server_new_diff;
	PyObject *server_req_key;
	PyObject *server_listen_repo;
	PyObject *main;

	PyObject *cb;

	void *data;
	receive_cb receive;
} client_module_t;

static client_module_t mod = {0};

void client_module_finalize()
{
	if(mod.module) Py_DECREF(mod.module);

	if(mod.server_connect) Py_XDECREF(mod.server_connect);
	if(mod.server_new_diff) Py_XDECREF(mod.server_new_diff);
	if(mod.server_req_key) Py_XDECREF(mod.server_req_key);
	if(mod.server_listen_repo) Py_XDECREF(mod.server_listen_repo);
	if(mod.main) Py_XDECREF(mod.main);

	if(mod.cb) Py_XDECREF(mod.cb);

    Py_Finalize();
}

static PyObject *c_wraper(PyObject *self, PyObject *args)
{
	char *repo;
	char *diff;
	int len;

	// parse arguments
	if(PyArg_ParseTuple(args, "ss#", &repo, &diff, &len))
	{
		mod.receive(mod.data, repo, diff, len);
	}
	else
	{
		printf("Arguments wrong\n");
	}

    Py_RETURN_NONE;
}

void client_module_run()
{
	PyGILState_STATE _state = PyGILState_Ensure();
	PyObject_CallObject(mod.main, NULL);
	PyGILState_Release(_state);
}

void client_module_init(void *data, receive_cb receive)
{
    Py_Initialize();
	/* Py_InitializeEx(1); */
	PyEval_InitThreads();

	PyObject* sysPath = PySys_GetObject((char*)"path");
	char cwd[1024];
	if(!getcwd(cwd, sizeof(cwd)))
	{
		exit(1);
	}

	PyObject* programName = PyUnicode_FromString(cwd);
	PyList_Append(sysPath, programName);
	Py_DECREF(programName);
	mod.module = PyImport_ImportModule("client");

	wchar_t *name[5] = {L"pync"};
    PySys_SetArgv(1, (wchar_t**)name);

    if(mod.module == NULL)
	{
		client_module_finalize();
		exit(1);
	}
	mod.server_connect =
		PyObject_GetAttrString(mod.module, "server_connect");

	mod.server_new_diff =
		PyObject_GetAttrString(mod.module, "server_new_diff");

	mod.server_req_key =
		PyObject_GetAttrString(mod.module, "server_req_key");

	mod.server_listen_repo =
		PyObject_GetAttrString(mod.module, "server_listen_repo");

	mod.main =
		PyObject_GetAttrString(mod.module, "main");


	static PyMethodDef cb_ml = {"c_wraper", c_wraper, METH_VARARGS, "doc"};
	mod.cb = PyCFunction_New(&cb_ml, NULL);

	mod.data = data;
	mod.receive = receive;

	PyGILState_STATE _state = PyGILState_Ensure();
	PyGILState_Release(_state);

	/* PyThreadState *_state = PyEval_SaveThread(); */

	/* PyEval_RestoreThread(_state); */

}

void server_connect(const char *ip, long port, const char *name,
		const char *org)
{
	/* Py_BEGIN_ALLOW_THREADS */
	PyGILState_STATE _state = PyGILState_Ensure();
    PyObject *pArgs = PyTuple_New(5);
    PyObject *ipValue = PyUnicode_FromString(ip);
    PyObject *nameValue = PyUnicode_FromString(name);
    PyObject *orgValue = PyUnicode_FromString(org);
    PyObject *portValue = PyLong_FromLong(port);

    PyTuple_SetItem(pArgs, 0, ipValue);
    PyTuple_SetItem(pArgs, 1, portValue);
    PyTuple_SetItem(pArgs, 2, mod.cb);
    PyTuple_SetItem(pArgs, 3, nameValue);
    PyTuple_SetItem(pArgs, 4, orgValue);

    PyObject_CallObject(mod.server_connect, pArgs);

	Py_DECREF(portValue);
	Py_DECREF(ipValue);
	Py_DECREF(nameValue);
	Py_DECREF(orgValue);

	PyGILState_Release(_state);
	/* Py_END_ALLOW_THREADS */
}

void server_new_diff(const char *repo, const char *diff, unsigned int len)
{
	/* Py_BEGIN_ALLOW_THREADS */
	PyGILState_STATE _state = PyGILState_Ensure();
    PyObject *pArgs = PyTuple_New(2);
    PyObject *pRepo = PyUnicode_FromString(repo);
    PyObject *pDiff = PyBytes_FromStringAndSize(diff, len);

    PyTuple_SetItem(pArgs, 0, pRepo);
    PyTuple_SetItem(pArgs, 1, pDiff);

    PyObject_CallObject(mod.server_new_diff, pArgs);

	Py_DECREF(pRepo);
	Py_DECREF(pDiff);

	PyGILState_Release(_state);
	/* Py_END_ALLOW_THREADS */
}

void server_req_key(const char *repo)
{

}

void server_listen_repo(const char *name, const char *dir)
{
	/* Py_BEGIN_ALLOW_THREADS */
	PyGILState_STATE _state = PyGILState_Ensure();

    PyObject *pArgs = PyTuple_New(2);
    PyObject *pName = PyUnicode_FromString(name);
    PyObject *pDir = PyUnicode_FromString(dir);

    PyTuple_SetItem(pArgs, 0, pName);
    PyTuple_SetItem(pArgs, 1, pDir);

    PyObject_CallObject(mod.server_listen_repo, pArgs);
	/* Py_DECREF(pRepo); */
	/* PyErr_Print(); */

	Py_DECREF(pName);
	Py_DECREF(pDir);

	PyGILState_Release(_state);
	/* Py_END_ALLOW_THREADS */
}


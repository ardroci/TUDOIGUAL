LIBS = -lutil -lpthread -lmba $(shell python-config --libs)
CFLAGS = -g3  -Wall
PY_CFLAGS = $(shell python-config --cflags)

OS := $(shell uname)
ifeq ($(OS),Linux)
	# LIBS += -lfswatch
	# CFLAGS += -D__APPLE__
else
	LIBS += -lfswatch
endif

SRCS = main.c diff.c watcher.c onexit.c
PY_SRCS = client_module.c

OBJS = $(patsubst %.c, %.o, $(SRCS))
PY_OBJS = $(patsubst %.c, %.py.o, $(PY_SRCS))

all: $(OBJS) $(PY_OBJS)
	cc $(OBJS) $(PY_OBJS) -o pyncd $(LIBS)

%.o: %.c
	cc -c $< -o $@ $(CFLAGS)

%.py.o: %.c
	cc -c $< -o $@ $(PY_CFLAGS) $(CFLAGS)

clean:
	-rm cert*
	-rm .keys/*
	-rm repos*
	-rm pyncd *.o
	
run:
	./pyncd

run2:
	mkdir -p ../client2_test
	cp pyncd ../client2_test
	cp client.py ../client2_test
	# cd ../client2_test
	# ./pyncd

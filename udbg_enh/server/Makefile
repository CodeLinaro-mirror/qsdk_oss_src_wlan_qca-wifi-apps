CC ?= gcc
CFLAGS += -Wall -g -Iinc -fPIC

TARGETS = udbg_enh_server udbg_enh_server_cli

DESTDIR ?=
BINDIR = $(DESTDIR)/usr/local/bin

SERVER_SRCS = src/capture.c src/config.c src/server.c src/internal.c src/server_ctrl_socket.c src/utils.c
SERVER_OBJS = $(SERVER_SRCS:.c=.o)

CLI_SRCS = src/server_cli.c src/utils.c
CLI_OBJS = $(CLI_SRCS:.c=.o)

OBJS = $(sort $(SERVER_OBJS) $(CLI_OBJS))

.PHONY: all install clean

all: $(TARGETS)

udbg_enh_server: $(SERVER_OBJS)
	$(CC) $(SERVER_OBJS) -o $@ $(LDFLAGS)

udbg_enh_server_cli: $(CLI_OBJS)
	$(CC) $(CLI_OBJS) -o $@ $(LDFLAGS)

install: all
	install -d $(BINDIR)
	install -m 0755 udbg_enh_server $(BINDIR)/udbg_enh_server
	install -m 0755 udbg_enh_server_cli $(BINDIR)/udbg_enh_server_cli

clean:
	rm -f $(TARGETS) $(OBJS)

CC ?= gcc
CFLAGS += -Wall -Werror -g -I. -fPIC
LDFLAGS += -lpthread -shared

TARGET = libhost_subsystem_handler.so

DESTDIR ?=
LIBDIR = $(DESTDIR)/usr/lib

SRCS = utils.c uio.c actions.c subsys_core.c da_interface.c
OBJS = $(SRCS:.c=.o)

.PHONY: all install clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

install: all
	install -d $(LIBDIR)
	install -m 0755 $(TARGET) $(LIBDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)

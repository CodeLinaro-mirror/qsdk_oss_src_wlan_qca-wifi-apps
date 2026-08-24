CC ?= gcc
CFLAGS += -Wall -g -Iinc -fPIC
LDFLAGS += -shared

TARGET = libudbg_client_core.so

DESTDIR ?=
LIBDIR = $(DESTDIR)/usr/local/lib

SRCS = src/core.c src/proto.c src/internal.c src/nlctrl_nl80211.c
OBJS = $(SRCS:.c=.o)

.PHONY: all install clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -shared -o $(TARGET) $(OBJS)

install: all
	install -d $(LIBDIR)
	install -m 0755 $(TARGET) $(LIBDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)

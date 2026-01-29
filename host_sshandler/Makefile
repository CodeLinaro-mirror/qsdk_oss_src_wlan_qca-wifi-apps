CC = gcc
CFLAGS = -Wall -Werror -g -I.
LDFLAGS = -lpthread

TARGET = host_sshandler

SRCS = main.c utils.c uio.c actions.c subsys_core.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c subsys_core.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

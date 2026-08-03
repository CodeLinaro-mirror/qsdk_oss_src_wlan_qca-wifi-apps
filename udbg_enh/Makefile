.PHONY: all clean install

SUBDIRS=$(wildcard client) $(wildcard server)

all:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir; done

clean:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean; done

install:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir install; done

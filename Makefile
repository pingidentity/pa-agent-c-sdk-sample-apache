#
# Makefile for building the PingAccess Agent SDK for C Sample
# 
# This Makefile uses the apxs tool to build the Apache sample module, which
# implicitly will use the gcc compiler.
#

all: mod_paa.so

mod_paa.so: .libs/mod_paa.so
	cp .libs/mod_paa.so .

RHEL_PLATFORM = $(shell if [ -z "`cat /etc/redhat-release | grep 'release 6'`" ]; then echo rhel7; else echo rhel6; fi)

APACHE_INCLUDE_FLAGS := -I. -I../include

APACHE_LIB_FLAGS := -L../lib/$(RHEL_PLATFORM)/x86_64/static \
   	-lpaa-cache-zmq \
	-lpaa-config-filesystem \
	-lpaa-http-client-curl \
	-lpaa \
	-lpaa-common \
	-lzmq \
	-lcurl \
	-lpcre

APACHE_SRC_FILES := mod_paa.c apache-http-server-facade.c

.libs/mod_paa.so:
	apxs -c $(APACHE_INCLUDE_FLAGS) $(APACHE_LIB_FLAGS) -o mod_paa.so $(APACHE_SRC_FILES)

.PHONY: clean
clean: 
	rm -f *.so *.o *.lo *.slo *.la
	rm -rf .libs

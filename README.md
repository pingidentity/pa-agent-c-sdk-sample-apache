# PingAccess Agent SDK Sample #

This directory contains a sample Apache agent that implements the PingAccess
Agent Protocol.

## Supported Platforms ##

- Red Hat Enterprise Linux 6 (RHEL6), 64-bit
- Red Hat Enterprise Linux 7 (RHEL7), 64-bit

## Runtime Dependencies ##

The following are required to build an run this sample agent:

1. PingAccess Agent SDK for C
2. PingAccess 4.0.3 or later and a valid license
3. PingFederate 7.1.x or 8.0.x or later and a valid license
4. Properly configured Apache HTTP server instance in which to install the agent module

## Installing the PingAccess Agent SDK for C ##

1. Download from x
2. Unzip in desired install location

## Installing Build Dependencies ##

The sample requires the installation of some build-time dependencies. Some 
dependencies are available from the RHEL repositories, but a few are shipped
in lib/${platform}/dependencies.

Run the following yum command as root to install all the dependencies:

    yum install httpd-devel.x86_64 libcurl-devel.x86_64 pcre-devel.x86_64 gcc.x86_64

For RHEL6, run the following yum command as root to install the provided dependencies:

    yum install ../lib/rhel6/x86_64/dependencies/*.rpm

For RHEL7, run the following yum command as root to install the provided dependencies:

    yum install ../lib/rhel7/x86_64/dependencies/*.rpm

## Building ##

The sample Apache agent module can be built using the provided GNU Make
Makefile. Either modify the Make file to set the variable PAA_SDK_INSTALL_DIR to the base of the
the unzipped C SDK distribution installed earlier, or specify it on the command line. For example:

    make PAA_SDK_INSTALL_DIR=/usr/local/pingaccess-agent-c-sdk

The build process creates ``mod_paa.so``, as well as other intermediate artifacts.

## Deploying ##

These instructions assume Apache is installed using the RHEL Apache RPMs, which
places the ``HTTPD_ROOT`` at ``/etc/httpd``. If you have installed Apache in a
different location, replace ``/etc/httpd`` in the following paths with your
value for ``HTTPD_ROOT``.

The following instructions must be run with root privileges.

### RHEL6 ###

1. Copy ``mod_paa.so`` to ``/etc/httpd/modules``
2. Copy ``paa.conf`` to ``/etc/httpd/conf.d``
3. Restart Apache

### RHEL7 ###

1. Copy ``mod_paa.so`` to ``/etc/httpd/modules``
2. Copy ``paa.conf`` to ``/etc/httpd/conf.modules.d/10-paa.conf``
3. Restart Apache

After deploying the agent, obtain an agent.properties from the PingAccess Admin
Console to configure the agent with the details necessary to contact the
PingAccess Policy Server.

# PingAccess Agent SDK for C Sample #

This directory contains a sample Apache agent that implements the PingAccess
Agent Protocol using the Agent SDK for C.

## Supported Platforms ##

- Red Hat Enterprise Linux 7 (RHEL7), 64-bit
- Red Hat Enterprise Linux 8 (RHEL8), 64-bit

## Runtime Dependencies ##

The following are required to build and run this sample agent:

1. [PingAccess 4.0.3 or later](https://www.pingidentity.com/en/resources/downloads/pingaccess.html)
and a [valid license](https://www.pingidentity.com/en/account/request-license-key.html)
2. [PingFederate 7.1.x or 8.0.x or later](https://www.pingidentity.com/en/resources/downloads/pingfederate.html)
and a [valid license](https://www.pingidentity.com/en/account/request-license-key.html)
3. Properly configured Apache HTTP server instance in which to install the agent module

## Installing the PingAccess Agent SDK for C ##

1. Download the [PingAccess Agent SDK for C](https://www.pingidentity.com/en/resources/downloads/pingaccess.html)
2. Unzip in desired install location
3. Within the remainder of this document, the base of the unzipped contents is known as ``PAA_SDK_INSTALL_DIR``

## Installing Build Dependencies ##

The sample requires the installation of some build-time dependencies. Some
dependencies are available from the RHEL repositories, but a few are shipped
in `${PAA_SDK_INSTALL_DIR}/lib/${platform}/dependencies` directory of the Agent SDK for C installation.

### RHEL 7

Run the following yum command as root to install all the dependencies:

    yum install httpd-devel.x86_64 libcurl-devel.x86_64 pcre-devel.x86_64 gcc.x86_64

For RHEL7, run the following yum command as root to install the provided dependencies:

    yum install ${PAA_SDK_INSTALL_DIR}/lib/rhel7/x86_64/dependencies/*.rpm

To support linking against ZeroMQ 4 without requiring the zeromq-devel package (which
conflicts with a zeromq package available from the EPEL repositories), manually add
the following link as root:

    ln -s /usr/lib64/libzmq.so.5 /usr/lib64/libzmq.so

### RHEL 8

Run the following yum command as root to install all the dependencies:

    dnf install httpd-devel.x86_64 libcurl-devel.x86_64 pcre-devel.x86_64 gcc.x86_64

For RHEL8, run the following yum command as root to install the provided dependencies:

    dnf install ${PAA_SDK_INSTALL_DIR}/lib/rhel8/x86_64/dependencies/*.rpm

To support linking against ZeroMQ 4 without requiring the zeromq-devel package (which
requires enabling the EPEL repositories), manually add the following link as root:

    ln -s /usr/lib64/libzmq.so.5 /usr/lib64/libzmq.so


## Building the Apache Agent Sample ##

The sample Apache agent module can be built using the provided GNU Make
Makefile. The base of the unzipped C SDK distribution installed earlier must be specified on the command line.
For example:

    make PAA_SDK_INSTALL_DIR=/usr/local/pingaccess-agent-c-sdk

The build process creates ``mod_paa.so``, as well as other intermediate artifacts.

## Deploying ##

These instructions assume Apache is installed using the RHEL Apache RPMs, which
places the ``HTTPD_ROOT`` at ``/etc/httpd``. If you have installed Apache in a
different location, replace ``/etc/httpd`` in the following paths with your
value for ``HTTPD_ROOT``.

The following instructions must be run with root privileges.

1. Copy ``mod_paa.so`` to ``/etc/httpd/modules``
2. Copy ``paa.conf`` to ``/etc/httpd/conf.modules.d/10-paa.conf``
3. Restart Apache

After deploying the agent, obtain an ``agent.properties`` from the PingAccess Admin
Console to configure the agent with the details necessary to contact the
PingAccess Policy Server.

## Support ##

- The most recent version of this sample application and project may be found at [Github](https://github.com/pingidentity/pa-agent-c-sdk-sample-apache).
- Customers and Partners may create cases via the [Ping Identity Support and Community Portal](https://support.pingidentity.com/s/).
- API Documentation for the PingAccess Agent SDK for C is hosted at the [Ping Identity Developer Portal](https://www.pingidentity.com/content/developer/en/explore.html)
- Additional Documentation for PingAccess Agent SDK for C can be found in the [Knowledge Center](https://docs.pingidentity.com/bundle/pingaccess-61/page/kyd1564006747350.html)

## Disclaimer ##
This software is open sourced by Ping Identity but not supported commercially as such. Any questions/issues
should be brought up for discussion on the [Ping Identity developer communities](https://support.pingidentity.com/s/community-home).
See also the DISCLAIMER file in this directory.

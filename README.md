# PingAccess Agent SDK for C Sample #

This directory contains a sample Apache agent that implements the PingAccess
Agent Protocol using the Agent SDK for C.

## Supported Platforms ##

- Red Hat Enterprise Linux 6 (RHEL6), 64-bit
- Red Hat Enterprise Linux 7 (RHEL7), 64-bit

## Runtime Dependencies ##

The following are required to build and run this sample agent:

1. [PingAccess 4.0.3 or later](https://www.pingidentity.com/en/products/downloads/pingaccess.html)
and a [valid license](https://developer.pingidentity.com/en/connect.html)
2. [PingFederate 7.1.x or 8.0.x or later](https://www.pingidentity.com/en/products/downloads/pingfederate.html)
and a [valid license](https://developer.pingidentity.com/en/connect.html)
3. Properly configured Apache HTTP server instance in which to install the agent module

## Installing the PingAccess Agent SDK for C ##

1. Download [PingAccess Agent SDK for C](https://www.pingidentity.com/en/products/downloads/pingaccess.html)
2. Unzip in desired install location
3. Within the remainder of this document, the base of the unzipped contents is known as ``PAA_SDK_INSTALL_DIR``

## Installing Build Dependencies ##

The sample requires the installation of some build-time dependencies. Some
dependencies are available from the RHEL repositories, but a few are shipped
in ${PAA_SDK_INSTALL_DIR}/lib/${platform}/dependencies directory of the Agent SDK for C installation.

Run the following yum command as root to install all the dependencies:

    yum install httpd-devel.x86_64 libcurl-devel.x86_64 pcre-devel.x86_64 gcc.x86_64

For RHEL6, run the following yum command as root to install the provided dependencies:

    yum install ${PAA_SDK_INSTALL_DIR}/lib/rhel6/x86_64/dependencies/*.rpm

For RHEL7, run the following yum command as root to install the provided dependencies:

    yum install ${PAA_SDK_INSTALL_DIR}/lib/rhel7/x86_64/dependencies/*.rpm

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

### RHEL6 ###

1. Copy ``mod_paa.so`` to ``/etc/httpd/modules``
2. Copy ``paa.conf`` to ``/etc/httpd/conf.d``
3. Restart Apache

### RHEL7 ###

1. Copy ``mod_paa.so`` to ``/etc/httpd/modules``
2. Copy ``paa.conf`` to ``/etc/httpd/conf.modules.d/10-paa.conf``
3. Restart Apache

After deploying the agent, obtain an ``agent.properties`` from the PingAccess Admin
Console to configure the agent with the details necessary to contact the
PingAccess Policy Server.

## Support ##

- The latest version of the PingAccess Agent SDK for C can be downloaded [here](https://www.pingidentity.com/en/products/downloads/pingaccess.html) (login required).
- The most recent version of this sample application and project may be found at [github](https://github.com/pingidentity/pa-agent-c-sdk-sample-apache).
- Customers and Partners may create cases via the [Ping Identity Support and Community Portal](https://ping.force.com/Support/Case_Create_Public).
- API Documentation for the PingAccess Agent SDK for C is hosted at the [Ping Identity Developer Portal](https://developer.pingidentity.com/content/dam/developer/documentation/pingaccess/agent-c-sdk/latest)
- Additional Documentation for PingAccess Agent SDK for C can be found in the [Knowledge Center](https://docs.pingidentity.com/bundle/pa_sm_agentSDKC)
- For developers using Java technologies, there is also a PingAccess Agent Sample application for Java, also hosted at github (link TBD)
- If you require integration with PingAccess via a different technology, we have published the protocol interaction with the engine as the PingAccess Agent Protocol specification (TBP), which is hosted at the Ping Identity Developer Portal (login required).

## Disclaimer ##
This software is open sourced by Ping Identity but not supported commercially as such. Any questions/issues
should be brought up for discussion on the [Ping Identity developer communities](https://community.pingidentity.com/collaborate).
See also the DISCLAIMER file in this directory.

# PingAccess Agent SDK Sample #

This directory contains a sample Apache agent that implements the PingAccess
Agent Protocol.

## Supported Platforms ##

- Red Hat Enterprise Linux 6 (RHEL6), 64-bit
- Red Hat Enterprise Linux 7 (RHEL7), 64-bit

## Runtime Dependencies ##

The following are required to build an run this sample agent:

1. [PingAccess 4.0.3 or later](https://www.pingidentity.com/en/products/downloads/pingaccess.html)
and a [valid license](https://developer.pingidentity.com/en/connect.html)
2. [PingFederate 7.1.x or 8.0.x or later](https://www.pingidentity.com/en/products/downloads/pingfederate.html)
and a [valid license](https://developer.pingidentity.com/en/connect.html)
3. Properly configured Apache HTTP server instance in which to install the agent module

## Installing the PingAccess Agent SDK for C ##

1. Download [PingAccess Agent SDK for C](https://www.pingidentity.com/en/products/downloads/pingaccess.html)
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

## Support ##

- The most recent version of this sample application and project may be found at [github](https://github.com/pingidentity/pa-agent-c-sdk-sample-apache).
- Navigate to the [wiki page at github](https://github.com/pingidentity/pa-agent-c-sdk-sample-apache/wiki) for Frequently Asked Questions
- Any other questions/issues can be sent to the [github issues tracker](https://github.com/pingidentity/pa-agent-c-sdk-sample-apache/issues) or discussed on the [Ping Identity developer communities](https://community.pingidentity.com/collaborate)
- Customers and Partners may create cases via the [Ping Identity Support and Community Portal](https://ping.force.com/Support/Case_Create_Public).
- The latest version of the PingAccess Agent SDK for C can be downloaded [here](https://www.pingidentity.com/en/products/downloads/pingaccess.html) (login required).
- API Documentation for the PingAccess Agent SDK for C is hosted at the [Ping Identity Developer Portal](https://developer.pingidentity.com/content/dam/developer/documentation/pingaccess/agent-c-sdk/1.0.1/index.html)
- Additional Documentation for PingAccess Agent SDK for C can be found in the [Knowledge Center](https://documentation.pingidentity.com/pingaccess/pa40/index.shtml#pa_c_Agent_SDK_Preface.html)
- For developers using Java technologies, there is also a PingAccess Agent Sample application for Java, also hosted at github (link needs to be updated)
- If you require integration with PingAccess via a different technology, or if you wish to integrate directly with PingAccess via REST, we have published the protocol interaction with the engine as the PingAccess Agent Protocol specification (TBP), which is hosted at the Ping Identity Developer Portal (login required).

## Disclaimer ##
This software is open sourced by Ping Identity but not supported commercially as such. Any questions/issues
should go to the [github issues tracker](https://github.com/pingidentity/pa-agent-c-sdk-sample-apache/issues) or be brought up
for discussion on the [Ping Identity developer communities](https://community.pingidentity.com/collaborate). See also the DISCLAIMER file in this directory.
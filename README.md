# tlmsp-tools

Tools for creating and testing TLMSP (ETSI TS 103 523-2) clients, middleboxes,
and servers.

* [Overview](#overview)
* [Building](#building)
  + [Dependencies](#dependencies)
  + [Initial build](#initial-build)
  + [Update build](#update-build)
  + [Debug build](#debug-build)
* [Running](#running)
  + [Configuration](#configuration)
  + [tlmsp-client, tlmsp-mb, tlmsp-server](#tlmsp-client--tlmsp-mb--tlmsp-server)
  + [apache-httpd](#apache-httpd)
  + [curl](#curl)

## Overview

tlmsp-tools provides several libraries and executables:

tlmsp-tools component   | Description
------------------------|-------------------
tlmsp-client            | Client program
tlmsp-mb                | Middlebox program
tlmsp-server            | Server program
libdemo                 | Common components for tlmsp-{client, mb, server}
libtlmsp-cfg            | Library for parsing and accessing UCL-based configuration files
libtlmsp-util           | Utility routines of interest to multiple TLMSP programs
libucl                  | Local build of libucl, as it isn't available on all platforms

<br>
tlmsp-tools also serves to coordinate the building of additional TLMSP-enabled
packages:
<br><br>

Additional components | Description
----------------------|---------------------
apache-httpd          | Apache httpd version that can serve pages over TLMSP
curl                  | curl version that can fetch pages over TLMSP
openssl               | OpenSSL modified to support TLMSP; used by apache, curl, and tlmsp-tools

## Building

### Dependencies

tlmsp-tools requires:
 * autotools
 * clang
 * libev
 * libpcre2
 * parallel

apache-httpd additionally requires:
 * libexpat
 * libpcre (old version)

On Ubuntu 18.04 LTS, the following obtains all of the necessary
pieces:

`sudo apt-get install autoconf clang gettext libexpat1-dev libpcre3-dev libpcre2-dev libtool-bin libev-dev parallel pkg-config`

### Initial build
```
# Starting in some <directory_root>, resulting in installation to 
# <directory_root>/install
mkdir tlmsp
cd tlmsp
git clone git@forge.etsi.org:cyber/tlmsp-tools.git
cd tlmsp-tools/build
./build.sh

# You will now have
# tlmsp/
#     install/
#     apache-httpd/
#     curl/
#     openssl/
#     tlmsp-tools/
```

Adjust your `PATH` to include `<directory_root>/tlmsp/install/bin` ahead of
any system paths that may contain executables with the same names.

Adjust your `LD_LIBRARY_PATH` to include
`<directory_root>/tlmsp/install/lib` ahead of any other system paths that
may contain libraries with the same names.

Set TLMSP_UCL to `<directory_root>/tlmsp/install/share/tlmsp-tools/examples`.

Scripts that can be sourced in shell init files to set up the environment as 
described above are installed in `<directory_root>/tlmsp/install/share/tlmsp-tools`.

Self-signed certificates and corresponding private keys (sufficient to satisfy
the default requirements for a client, server, and maximum number of
middleboxes) are installed under `<install_dir>/etc/pki` and
`<install_dir>/etc/pki/private`, respectively.

### Update build

After an initial build has been done, the following will pick up all source
changes, reconfigure, rebuild, and reinstall.

```
# While in tlmsp-tools/build
git pull
./build.sh -u
```

### Debug build

Add '-d' to the build.sh options used in order to configure and build with
compiler optimizations disabled, and compiler debug symbols and per-package
extra debug mechanisms engaged.

## Running

### Configuration

All of the programs obtain their TLMSP-related configuration from a file whose
format is described in `tlmsp-tools/libtlmsp-cfg/everything.ucl`.  The
configuration file defines:

* The TLMSP entities
* The PKI configuration for each entity
* The network topology
* The TLMSP contexts being used
* The access rights of each middlebox for each context
* For tlmsp-client, tlmsp-mb, and tlmsp-server, match-action specifications
  ('activities') that determine their behavior

The following table summarizes the blocks from the configuration file that each
program consumes.

Program      | Contexts | Client | Middleboxes | Server | Activities | Notes
:------------|:--------:|:------:|:-----------:|:------:|:----------:|:---------
tlmsp-client |    X     |   X    |      X      |   X    |      X     |
tlmsp-mb     |          |        |      X      |   X    |      X     | Context and server address details normally obtained from the wire; when transparent middleboxes are configured, the transparency emulation sometimes requires a peek at the server block in the config file.
tlmsp-server |    X     |        |      X      |   X    |      X     | 
apache-httpd |    X     |        |      X      |        |            | Server address and PKI config come from the apache configuration
curl         |    X     |   X    |      X      |   X    |            | Client used only for client address; Server used only for address to validate command line URL

<br>

Sample configuration files are installed in `<install_dir>/share/tlmsp-tools/examples`.

### tlmsp-client, tlmsp-mb, tlmsp-server

The server and middlebox(es) can be started in any order.  The client, of course, needs to be started last.

```
# -P turns on 'presentation' style logging, which narrates the match-action activity in a relatively uncluttered way
tlmsp-server -c config.ucl -P
```
```
# middleboxes require specification of which one in the given config file to run
tlmsp-mb -c config.ucl -t mbox1 -P

# or which ones
tlmsp-mb -c config.ucl -t mbox1 -t mbox2 -P

# or all
tlmsp-mb -c config.ucl -a -P
```
```
tlmsp-client -c config.ucl -P
```

Aside from configurable logging, these three programs will print out summary
statistics in response to a specific signal.  Under FreeBSD, this is SIGINFO,
which can be delivered to a process controlling a terminal by using Ctrl+T.
Under Linux, one has to resort to `kill -SIGUSR1 <pid>` from another terminal.

### apache-httpd

The apache-httpd configuration is installed at `<install_dir>/etc/apache24/httpd.conf`
and includes `<install_dir>/etc/apache24/httpd_tlmsp.conf`, which in turn 
defines several virtual hosts:

| Listen address | Configuration file              |
|----------------|---------------------------------|
| localhost:4443 | ${TLMSP_UCL}/apache.ucl         |
| localhost:4444 | ${TLMSP_UCL}/apache.1mbox.ucl   |
| localhost:4445 | ${TLMSP_UCL}/apache.2mbox.ucl   |
| localhost:4446 | ${TLMSP_UCL}/apache.251mbox.ucl |

<br>
The apache-httpd TLMSP integration requires the UCL file to define two contexts,
one with the tag 'header' and one with the tag 'body', into which it places
response headers and bodies, respectively.

Pages are served out of `<install_dir>/share/apache24/htdocs` and logs can be
found in `<install_dir>/var/logs`.

```
# Start apache in the single-worker, foreground mode
httpd -X
```
```
# If using the server on port 4444, a middlebox will need to be started
tlmsp-mb -c ${TLMSP_UCL}/apache.1mbox.ucl -t mbox1 -P
```
```
# Run tlmsp-client, here against the server on port 4443
tlmsp-client -c ${TLMSP_UCL}/apache.ucl -P

# or use curl, again assuming against the server on port 4443
curl --tlmsp ${TLMSP_UCL}/apache.ucl https://localhost:4443 -k -v
```

Either client should successfully fetch the default index.html that installs
with apache, which consists of:

```
<html><body><h1>It works!</h1></body></html>
```

### curl

The curl TLMSP integration requires the UCL file to define two contexts, one
with the tag 'header' and one with the tag 'body', into which it places request
headers and bodies, respectively.

Also, the server hostname and port indicated in the URL on the command line
must match the hostname and port indicated by the server address in the UCL file.
curl continues to require an explicit URL in TLMSP mode so that different request
paths can be specified without having to edit the UCL file.

```
tlmsp-server -c ${TLMSP_UCL}/curl.ucl -P
```
```
curl --tlmsp ${TLMSP_UCL}/curl.ucl https://localhost:10254 -k -v
```

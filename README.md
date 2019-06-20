# tlmsp-tools

Tools for creating and testing TLMSP (ETSI TS 103 523-2) clients, middleboxes, and servers.

Executable   | Purpose
-------------|---------------
tlmsp-client | Client program
tlmsp-mb     | Middlebox program
tlmsp-server | Server program

# Building

```
git clone git@forge.etsi.org:cyber/tlmsp-tools.git
git clone git@forge.etsi.org:cyber/tlmsp-openssl.git
mkdir tlmsp-install
cd tlmsp-tools/build
./initial-build.sh $(realpath ../../tlmsp-install)
```

The tools can then be run directly out of tlmsp-tools/, or more
generally by adding the tlmsp-install/bin path to PATH and
tlmsp-install/lib path to LD\_LIBRARY\_PATH.

## Dependencies

tlmsp-tools requires:
 * autotools
 * clang
 * libev
 * libpcre2.

On Ubuntu 18.04 LTS, the following obtains all of the necessary
pieces:
`sudo apt-get install autoconf clang gettext libpcre2-dev libtool libev-dev pkg-config`

#!/bin/sh


usage() {
    echo "Usage: $0 local_install_dir"
}


if [ $# -ne 1 ]; then
    usage $0
    exit 3
fi
local_install_dir=$1
ucl_dir="$(pwd)/libucl"

if [ ! -d "${local_install_dir}" ]; then
    echo "Local installation directory '${local_install_dir}' does not exist"
    exit 4
fi

if [ ! -f "${local_install_dir}/include/openssl/tlmsp.h" ]; then
    echo "The TLMSP version of OpenSSL needs to be built and installed first"
    exit 5
fi


echo "Configuring build for local installation directory '${local_install_dir}'"
echo "Running autoreconf (this may take 10 seconds or so)"
autoreconf -i


# tlmsp-tools needs clang, and it needs proper include path ordering,
# which requires working around various issues with autoconf with
# command-line overrides.
os=$(uname -s)
if [ $os = "FreeBSD" ]; then
    CC=
    CPPFLAGS="CPPFLAGS=\"-I${ucl_dir}/include -I${local_install_dir}/include -I/usr/local/include\""
    LDFLAGS="LDFLAGS=\"-L${local_install_dir}/lib -L/usr/local/lib\""
elif [ $os = "Linux" ]; then
    CC="CC=clang"
    CPPFLAGS="CPPFLAGS=\"-I${ucl_dir}/include -I${local_install_dir}/include\""
    LDFLAGS="LDFLAGS=\"-L${local_install_dir}/lib\""
fi

config_cmd="./configure ${CC} ${CPPFLAGS} ${LDFLAGS} --with-libssl-prefix=${local_install_dir} --prefix=${local_install_dir}"
echo "Running ${config_cmd}"
eval ${config_cmd}

#!/bin/sh
#
# This script is for performing an initial configuration, build, and
# install of TLMSP-enabled openssl and tlmsp-tools.
#

usage() {
    echo "Usage: $0 local_install_dir [make_args]"
}


if [ $# -lt 1 ]; then
    usage $0
    exit 3
fi
local_install_dir=$1
shift
build_script_dir=$(pwd)
tlmsp_tools_dir=$(pwd)/..
openssl_dir=${build_script_dir}/../../openssl

if [ ! -f ${build_script_dir}/$(basename $0) ]; then
    echo "This script is intended to be run from the directory that contains it"
    exit 4
fi
if [ ! -d ${openssl_dir} ]; then
    echo "The openssl source directory needs to be alongside the tlmsp-tools directory"
    exit 5
fi
if [ ! -f "${openssl_dir}/include/openssl/tlmsp.h" ]; then
    echo "The openssl source directory does include TLMSP support"
    exit 6
fi
if [ ! -d "${local_install_dir}" ]; then
    echo "Local installation directory '${local_install_dir}' does not exist"
    exit 7
fi

echo "Configuring OpenSSL"
cd ${openssl_dir}
./config --prefix=${local_install_dir}
if [ $? -ne 0 ]; then
    echo "OpenSSL configuration failed"
    exit 8
fi

echo "Building OpenSSL"
make "$@"
if [ $? -ne 0 ]; then
    echo "OpenSSL build failed"
    exit 9
fi

echo "Installing OpenSSL"
make install_sw
if [ $? -ne 0 ]; then
    echo "OpenSSL installation failed"
    exit 10
fi

echo "Configuring tlmsp-tools"
cd ${tlmsp_tools_dir}
./buildconf.sh ${local_install_dir}
if [ $? -ne 0 ]; then
    echo "tlmsp-tools configuration failed"
    exit 11
fi

echo "Building tlmsp-tools"
make "$@"
if [ $? -ne 0 ]; then
    echo "tlmsp-tools build failed"
    exit 12
fi

echo "Installing tlmsp-tools"
make install
if [ $? -ne 0 ]; then
    echo "tlmsp-tools installation failed"
    exit 13
fi

echo "Success"

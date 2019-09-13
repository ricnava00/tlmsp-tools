#!/bin/sh
#
# This script is for configuring tlmsp-tools prior to building.
#

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "    -d                 Configure for a debug build"
    echo "    -h                 Print this help message"
    echo "    -i  <install_dir>  Set installation directory [default: ${script_dir}/../install]"
}

# echo given message to stdout such that it stands out
announce() {
    echo ">>>" $@
}

# like announce, but for critical messages
alert() {
    echo "!!!" $@
}

require_success() {
    eval $@
    if [ $? -ne 0 ]; then
	alert "command failed:" $@
	exit 1
    fi
}

require_dir() {
    local dirname="$1"
    local fail_msg="$2"

    if [ ! -d ${dirname} ]; then
	alert ${fail_msg}
	exit 1
    fi
}

require_file() {
    local filename="$1"
    local fail_msg="$2"

    if [ ! -f ${filename} ]; then
	alert ${fail_msg}
	exit 1
    fi
}


build_script_dir=$(pwd)
require_file "${build_script_dir}/$(basename $0)" \
	     "This script is intended to be run from the directory that contains it"
ucl_dir=${build_script_dir}/libucl
install_dir=${build_script_dir}/../install
debug=

args=`getopt dhi: $*`
if [ $? -ne 0 ]; then
    usage $0
    exit 1
fi
set -- $args
while true; do
    case "$1" in
	-d)
	    debug=yes
	    shift
	    ;;
	-h)
	    usage $0
	    exit 0
	    ;;
	-i)
	    shift
	    install_dir=$1
	    shift
	    ;;
	--)
	    shift; break
	    ;;
    esac
done
if [ $# -ne 0 ]; then
    usage $0
    exit 1
fi

silent_rules=--disable-silent-rules

require_dir ${install_dir} \
	    "The installation directory '${install_dir} does not exist"
# Simplify installation path
install_dir=$(realpath ${install_dir})

require_file "${install_dir}/include/openssl/tlmsp.h" \
	     "The OpenSSL installation does not include TLMSP support"

announce "Configuring build for installation directory '${install_dir}'"
announce "Running autoreconf (this may take 15 seconds or so)"
require_success autoreconf -i


# tlmsp-tools needs clang, and it needs proper include path ordering,
# which requires working around various issues with autoconf by using
# command-line overrides.
os=$(uname -s)
if [ $os = "FreeBSD" ]; then
    CC=
    CPPFLAGS="'CPPFLAGS=-I${ucl_dir}/include -I${install_dir}/include -I/usr/local/include'"
    LDFLAGS="'LDFLAGS=-L${install_dir}/lib -L/usr/local/lib'"
elif [ $os = "Linux" ]; then
    CC="CC=clang"
    CPPFLAGS="'CPPFLAGS=-I${ucl_dir}/include -I${install_dir}/include'"
    LDFLAGS="'LDFLAGS=-L${install_dir}/lib'"
fi

require_success ./configure \
		${CC} ${CPPFLAGS} ${LDFLAGS} \
		--prefix=${install_dir} \
		--datadir=${install_dir}/share/tlmsp-tools \
		--with-libssl-prefix=${install_dir} \
		${silent_rules} \
		${debug:+--enable-debug}

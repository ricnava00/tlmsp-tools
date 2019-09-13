#!/bin/sh
#
# This script generates self-signed certificates (and corresponding
# private keys) for demo purposes.
#
# If a tag is not supplied, the output files are named key.pem and
# cert.pem.
#
# If a tag is supplied, the output files are named <tag>-key.pem and
# <tag>-cert.pem.
#
# If an output directory is not specified for the key or certificate
# file, the respective output directory will be the current working
# directory.
#

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "    -c <dir>  Specify output directory for the certificate file [default: current working directory]"
    echo "    -h        Print this help message"
    echo "    -k <dir>  Specify output directory for private key file [default: current working directory]"
    echo "    -t <tag>  Set installation directory [default: ${script_dir}/../install]"
}

key_out_dir=.
cert_out_dir=.
tag=
args=`getopt c:hk:t: $*`
if [ $? -ne 0 ]; then
    usage $0
    exit 1
fi
set -- $args
while true; do
    case "$1" in
	-c)
	    shift
	    cert_out_dir=$1
	    shift
	    ;;
	-h)
	    usage $0
	    exit 0
	    ;;
	-k)
	    shift
	    key_out_dir=$1
	    shift
	    ;;
	-t)
	    shift
	    tag=$1
	    shift
	    ;;
	--)
	    shift; break
	    ;;
    esac
done
if [ $# -gt 0 ]; then
    usage
    exit 1
fi

if [ ! -d ${key_out_dir} ]; then
    echo "Key output directory ${key_out_dir} does not exist"
    exit 1
fi

if [ ! -d ${cert_out_dir} ]; then
    echo "Certificate output directory ${cert_out_dir} does not exist"
    exit 1
fi

if [ -n "$tag" ]; then
    tag="${tag}-"
fi

key_name=${key_out_dir}/${tag}key.pem
cert_name=${cert_out_dir}/${tag}cert.pem
echo "Creating ${key_name} and ${cert_name}"
openssl req \
	-new \
	-newkey rsa:2048 \
	-days 365 \
	-nodes \
	-x509 \
	-keyout ${key_name} \
	-out ${cert_name} \
	-subj "/C=FR/O=ETSI/OU=TC CYBER/CN=localhost"
if [ $? -ne 0 ]; then
    echo "Create failed"
    exit 1
fi

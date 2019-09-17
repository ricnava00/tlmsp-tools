#!/bin/sh
#
# This script is for performing configuration, build, and install of
# TLMSP-enabled openssl, tlmsp-tools, and TLMSP-enabled apache and
# curl.
#
# The process is as follows:
#   - Obtain all missing sources
#   - If -u was given, update existing sources
#   - Configure all sources, unless -n was given and all sources were
#       already present
#   - Build all sources
#   - Install all sources
#   - If -u was not given, generate keys and certificates
#

usage() {
    echo "Usage: $0 [options] [make_args]"
    echo ""
    echo "Options:"
    echo "    --                 Use ahead of <make_args> if first make_arg begins with -"
    echo "    -d                 Configure for and perform debug builds"
    echo "    -h                 Print this help message"
    echo "    -i  <install_dir>  Set installation directory [default: ${script_dir}/../install]"
    echo "    -n                 Skip configure stages if all sources were present"
    echo "    -u                 Update existing sources"
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

require_file() {
    local filename="$1"
    local fail_msg="$2"

    if [ ! -f ${filename} ]; then
	alert ${fail_msg}
	exit 1
    fi
}

require_repo() {
    local destdir="$1"
    local repo="$2"
    local branch_or_tag="$3"
    local origdir

    origdir=$(pwd)
    if [ ! -d ${destdir} ]; then
	announce "Cloning ${repo} to ${destdir}"
	require_success git clone ${repo} ${destdir}
	require_success cd ${destdir}
	announce "Checking out ${branch_or_tag}"
	require_success git checkout ${branch_or_tag}

	if [ "${no_configure}" = "yes" ]; then
	    announce "Configure stages will be run as not all source trees were present"
	    no_configure=
	fi
    else
	announce "Repo ${repo} appears to already be cloned to ${destdir}"
	if [ "${update_build}" = "yes" ]; then
	    require_success cd ${destdir}
	    announce "Updating sources in ${destdir}"
	    git status | head -n 1 | grep -q 'HEAD detached'
	    if [ $? -eq 0 ]; then
		announce "No update required - sources are parked at tag ${branch_or_tag}"
	    else
		require_success git pull
	    fi
	fi
    fi
    cd ${origdir}
}

# Assumes it is being run in the top directory of a package
maybe_clean() {
    # If not doing an update build and there is a Makefile, clean
    if [ "${force_clean}" = "yes" -o \( "${update_build}" != "yes" -a -f Makefile \) ]; then
	# If configure will be run, clean all the configure-generated
	# files too, otherwise normal clean
	if [ "${do_configure}" = "yes" ]; then
	    announce "Performing distclean"
	    # OK if it fails, so no require_success here
	    make distclean
	else
	    announce "Performing clean"
	    # OK if it fails, so no require_success here
	    make clean
	fi
    fi
}

build_script_dir=$(pwd)
require_file "${build_script_dir}/$(basename $0)" \
	     "This script is intended to be run from the directory that contains it"

tlmsp_tools_dir=$(realpath ${build_script_dir}/..)
install_dir=${tlmsp_tools_dir}/../install
src_root=$(realpath ${tlmsp_tools_dir}/..)
debug=
update_build=
no_configure=
force_clean=yes
max_middleboxes=251
apache_httpd_first_port=4443

orig_args=$@
args=`getopt dhi:nu $*`
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
	-n)
	    no_configure=yes
	    shift
	    ;;
	-u)
	    update_build=yes
	    shift
	    ;;
	--)
	    shift; break
	    ;;
    esac
done

openssl_dir=${src_root}/tlmsp-openssl
openssl_repo=https://forge.etsi.org/rep/cyber/tlmsp-openssl.git
openssl_branch_or_tag=master-tlmsp

curl_dir=${src_root}/tlmsp-curl
curl_repo=https://forge.etsi.org/rep/cyber/tlmsp-curl.git
curl_branch_or_tag=master-tlmsp

apache_httpd_dir=${src_root}/tlmsp-apache-httpd
apache_httpd_repo=https://forge.etsi.org/rep/cyber/tlmsp-apache-httpd.git
apache_httpd_branch_or_tag=master-tlmsp

# dir set after overrides below
apache_apr_repo=https://github.com/apache/apr.git
apache_apr_branch_or_tag=1.7.0

# dir set after overrides below
apache_apr_util_repo=https://github.com/apache/apr-util.git
apache_apr_util_branch_or_tag=1.6.1

pki_public=${install_dir}/etc/pki
pki_private=${install_dir}/etc/pki/private

# If available, load overrides for default source tree and tag/branch
# names
if [ -f ./local-build-config.sh ]; then
    . ./local-build-config.sh
fi
apache_apr_dir=${apache_httpd_dir}/srclib/apr
apache_apr_util_dir=${apache_httpd_dir}/srclib/apr-util

silent_rules=--disable-silent-rules

os=`uname -s`
if [ $os = "FreeBSD" ]; then 
    num_cpus=`sysctl -n kern.smp.cpus`
    apache_httpd_configure_LDFLAGS="LDFLAGS=-L/usr/local/lib"
    apache_httpd_make_EXTRA_LIBS="EXTRA_LIBS=-liconv"
elif [ $os = "Linux" ]; then
    num_cpus=`grep -c ^processor /proc/cpuinfo`
else
    num_cpus=1
fi
max_cpus=10
if [ ${num_cpus} -gt ${max_cpus} ]; then
    num_cpus=${max_cpus}
fi

make_j=-j$(( ${num_cpus} * 2 ))

if [ ! -d ${install_dir} ]; then
    announce "Creating installation directory ${install_dir}"
    require_success mkdir -p ${install_dir}
fi

if [ ! -d ${pki_public} ]; then
    announce "Creating public pki directory ${pki_public}"
    require_success mkdir -p ${pki_public}
fi
if [ ! -d ${pki_private} ]; then
    announce "Creating private pki directory ${pki_private}"
    require_success mkdir -p ${pki_private}
    require_success chmod 700 ${pki_private}
fi

# Simplify names of directories that may have just been created as
# this can't be done before they exist
install_dir=$(realpath ${install_dir})
pki_public=$(realpath ${pki_public})
pki_private=$(realpath ${pki_private})

# Check to see if tlmsp-tools has advanced upstream
tlmsp_tools_update_check_failed=
if [ "${update_build}" = "yes" ]; then
    git remote update
    if [ $? -eq 0 ]; then
	git status -uno | grep -q 'branch is up to date'
	if [ $? -ne 0 ]; then
	    alert "======================================="
	    alert "tlmsp-tools needs to be updated:"
	    alert "git pull and re-run $0 ${orig_args}"
	    alert "======================================="
	    exit 1
	fi
    else
	tlsmp_tools_update_check_failed=yes
    fi
fi

# Fetch all sources
for s in openssl curl apache_httpd apache_apr apache_apr_util; do
    eval destdir=\$${s}_dir
    eval repo=\$${s}_repo
    eval branch_or_tag=\$${s}_branch_or_tag

    announce "Fetching ${repo} (${branch_or_tag}) to ${destdir}"
    require_repo ${destdir} ${repo} ${branch_or_tag}
done

do_configure=
if [ "${no_configure}" != "yes" ]; then
    do_configure=yes
fi

require_file "${openssl_dir}/include/openssl/tlmsp.h" \
	     "The OpenSSL source directory ${openssl_dir} does not include TLMSP support"

require_success cd ${openssl_dir}
maybe_clean
if [ "${do_configure}" = "yes" ]; then
    announce "Configuring OpenSSL"
    require_success ./config \
		    ${debug:+-d} \
		    --strict-warnings \
		    --prefix=${install_dir}
fi
announce "Building OpenSSL"
require_success make ${make_j} "$@"
announce "Installing OpenSSL"
require_success make install_sw

require_success cd ${tlmsp_tools_dir}
maybe_clean
tlmsp_tools_ucl_dir=${install_dir}/share/tlmsp-tools/examples
if [ "${do_configure}" = "yes" ]; then
    announce "Configuring tlmsp-tools"
    require_success ./buildconf.sh \
		    -i ${install_dir} \
		    ${debug:+-d}
fi
announce "Building tlmsp-tools"
require_success make ${make_j} "$@"
announce "Installing tlmsp-tools"
require_success make install

require_success cd ${curl_dir}
maybe_clean
if [ "${do_configure}" = "yes" ]; then
    announce "Configuring curl"
    require_success ./buildconf
    require_success ./configure \
		    --prefix=${install_dir} \
		    --with-ssl=${install_dir} \
		    --with-tlmsp-tools=${install_dir} \
		    ${silent_rules} \
		    ${debug:+--enable-debug} \
		    ${debug:+--disable-curldebug}
fi
announce "Building curl"
require_success make ${make_j} "$@"
announce "Installing curl"
require_success make install

require_success cd ${apache_httpd_dir}
maybe_clean
apache_httpd_conf_dir=${install_dir}/etc/apache24
if [ "${do_configure}" = "yes" ]; then
    announce "Configuring Apache HTTPD"
    require_success ./buildconf
    require_success ./configure \
		    ${apache_httpd_configure_LDFLAGS} \
		    --with-included-apr \
		    --with-ssl=${install_dir} \
		    --with-tlmsp-tools=${install_dir} \
		    --prefix=${install_dir} \
		    --includedir=${install_dir}/include/apache24 \
		    --datadir=${install_dir}/share/apache24 \
		    --sysconfdir=${apache_httpd_conf_dir} \
		    --localstatedir=${install_dir}/var \
		    --mandir=${install_dir}/share/man \
		    --libexecdir=${install_dir}/libexec/apache24 \
		    --with-port="127.0.0.1:${apache_httpd_first_port}\ https" \
		    ${debug:+--enable-debugger-mode}
fi
announce "Building Apache HTTPD"
require_success make ${make_j} ${apache_httpd_make_EXTRA_LIBS} "$@"
announce "Installing Apache HTTPD"
require_success make install

announce "Adjusting Apache HTTPD configuration files"
cd ${build_script_dir}
require_success sed -E -i.orig '"s/#(LoadModule ssl_module.+)/\\1/"' ${apache_httpd_conf_dir}/httpd.conf
require_success rm ${apache_httpd_conf_dir}/httpd.conf.orig
include_str="IncludeOptional ${apache_httpd_conf_dir}/httpd_tlmsp.conf"
grep -q "${include_str}" ${apache_httpd_conf_dir}/httpd.conf
if [ $? -ne 0 ]; then
    echo >> ${apache_httpd_conf_dir}/httpd.conf
    echo ${include_str} >> ${apache_httpd_conf_dir}/httpd.conf
fi
conf_file=${apache_httpd_conf_dir}/httpd_tlmsp.conf
if [ -f ${conf_file} ]; then
    timestamp=$(date +%Y%m%d-%H%M%S)
    backup_file=${conf_file}.${timestamp}
    if [ -f ${backup_file} ]; then
	sleep 2
	timestamp=$(date +%Y%m%d-%H%M%S)
	backup_file=${conf_file}.${timestamp}
    fi
    announce "Backing up existing ${conf_file} to ${backup_file}"
    require_success cp ${conf_file} ${backup_file}
fi
cat > ${conf_file} <<EOF

# Avoid warning about accept filters due to running from userland
AcceptFilter https none

<VirtualHost 127.0.0.1:${apache_httpd_first_port}>
    ServerName localhost
    SSLEngine on
    SSLCertificateFile "${pki_public}/server-cert.pem"
    SSLCertificateKeyFile "${pki_private}/server-key.pem"
    TLMSPConfigFile "${tlmsp_tools_ucl_dir}/apache.ucl"
</VirtualHost>

Listen 127.0.0.1:$(( ${apache_httpd_first_port} + 1 )) https

<VirtualHost 127.0.0.1:$(( ${apache_httpd_first_port} + 1 ))>
    ServerName localhost
    SSLEngine on
    SSLCertificateFile "${pki_public}/server-cert.pem"
    SSLCertificateKeyFile "${pki_private}/server-key.pem"
    TLMSPConfigFile "${tlmsp_tools_ucl_dir}/apache.1mbox.ucl"
</VirtualHost>

Listen 127.0.0.1:$(( ${apache_httpd_first_port} + 2 )) https

<VirtualHost 127.0.0.1:$(( ${apache_httpd_first_port} + 2 ))>
    ServerName localhost
    SSLEngine on
    SSLCertificateFile "${pki_public}/server-cert.pem"
    SSLCertificateKeyFile "${pki_private}/server-key.pem"
    TLMSPConfigFile "${tlmsp_tools_ucl_dir}/apache.2mbox.ucl"
</VirtualHost>

Listen 127.0.0.1:$(( ${apache_httpd_first_port} + 3 )) https

<VirtualHost 127.0.0.1:$(( ${apache_httpd_first_port} + 3 ))>
    ServerName localhost
    SSLEngine on
    SSLCertificateFile "${pki_public}/server-cert.pem"
    SSLCertificateKeyFile "${pki_private}/server-key.pem"
    TLMSPConfigFile "${tlmsp_tools_ucl_dir}/apache.251mbox.ucl"
</VirtualHost>

EOF

conf_dir=${install_dir}/ssl
require_success mkdir -p ${conf_dir}
conf_file=${conf_dir}/openssl.cnf
announce "Installing minimal openssl.cnf at ${conf_file}"
cat > ${conf_file} <<EOF
[ req ]
distinguished_name = req_dn

[ req_dn ]

EOF

if [ "${update_build}" != "yes" ]; then
    announce "Generating keys and certificates"
    require_success ./make_demo_cert.sh -c ${pki_public} -k ${pki_private} -t client
    require_success ./make_demo_cert.sh -c ${pki_public} -k ${pki_private} -t server
    require_success parallel ${make_j} \
		    ./make_demo_cert.sh \
		    -c ${pki_public} \
		    -k ${pki_private} \
		    -t mbox{} \
		    ::: $(seq ${max_middleboxes})
fi

setup_env_root=${install_dir}/share/tlmsp-tools/tlmsp-env
setup_env_sh=${setup_env_root}.sh
setup_env_csh=${setup_env_root}.csh
cat > ${setup_env_sh} <<EOF
export PATH=${install_dir}/bin:\$PATH
export LD_LIBRARY_PATH=${install_dir}/lib:\$LD_LIBRARY_PATH
export TLMSP_UCL=${tlmsp_tools_ucl_dir}
EOF
cat > ${setup_env_csh} <<EOF
setenv PATH ${install_dir}/bin:\$PATH
setenv LD_LIBRARY_PATH ${install_dir}/lib:\$LD_LIBRARY_PATH
setenv TLMSP_UCL=${tlmsp_tools_ucl_dir}
EOF
export TLMSP_SHELL_TYPE_TEST_VARIABLE=1 2>/dev/null
if [ $? -ne 0 ]; then
    announce "Ignore the above 'command not found' message"
    shell_type=csh
else
    shell_type=sh
fi

announce "Build complete"

if [ "${tlsmp_tools_update_check_failed}" = "yes" ]; then
    alert "============================================"
    alert "Unable to check if tlmsp-tools is up to date"
    alert "============================================"
    exit 1
fi

announce "Set up your environment by running this command (with the .), perhaps in your shell startup file:"
if [ "${shell_type}" = "sh" ]; then
    echo ". ${setup_env_sh}"
else
    echo ". ${setup_env_csh}"
fi

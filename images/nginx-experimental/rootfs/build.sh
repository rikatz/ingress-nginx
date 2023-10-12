#!/bin/bash

# Copyright 2023 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

export NGINX_VERSION=1.25.2

# Check for recent changes: https://github.com/vision5/ngx_devel_kit/compare/v0.3.2...master
export NDK_VERSION=0.3.2

# Check for recent changes: https://github.com/openresty/set-misc-nginx-module/compare/v0.33...master
# This module is used by `set_escape_uri` directive when using external auth. In the future
# it can be replaced by NJS or Lua
export SETMISC_VERSION=0.33

# Check for recent changes: https://github.com/openresty/headers-more-nginx-module/compare/v0.34...master
# This module is used by `more_set_headers` and `more_clear_headers` and in the future it can be replaced
# by NJS
# Current version is compatible with Nginx v1.25
export MORE_HEADERS_VERSION=607d1b1f32abc3de5a26deeeb827de19c1e842b9

# Check for recent changes: https://github.com/atomx/nginx-http-auth-digest/compare/v1.0.0...atomx:master
export NGINX_DIGEST_AUTH=1.0.0

# Check for recent changes: https://github.com/SpiderLabs/ModSecurity-nginx/compare/v1.0.3...master
export MODSECURITY_VERSION=1.0.3

# Check for recent changes: https://github.com/SpiderLabs/ModSecurity/compare/v3.0.8...v3/master
export MODSECURITY_LIB_VERSION=e9a7ba4a60be48f761e0328c6dfcc668d70e35a0

# Check for recent changes: https://github.com/coreruleset/coreruleset/compare/v3.3.2...v3.3/master
export OWASP_MODSECURITY_CRS_VERSION=v3.3.5

# Check for recent changes: https://github.com/openresty/lua-nginx-module/compare/v0.10.25...master
export LUA_NGX_VERSION=0.10.25

# Check for recent changes: https://github.com/openresty/stream-lua-nginx-module/compare/v0.0.13...master
export LUA_STREAM_NGX_VERSION=0.0.13

# Check for recent changes: https://github.com/openresty/lua-upstream-nginx-module/compare/dba0beaaeb0eaed758af3f4dc0c0464adeaedb1c...master
export LUA_UPSTREAM_VERSION=dba0beaaeb0eaed758af3f4dc0c0464adeaedb1c

# Check for recent changes: https://github.com/openresty/lua-cjson/compare/2.1.0.12...openresty:master
export LUA_CJSON_VERSION=2.1.0.12

# Check for recent changes: https://github.com/leev/ngx_http_geoip2_module/compare/a607a41a8115fecfc05b5c283c81532a3d605425...master
export GEOIP2_VERSION=a607a41a8115fecfc05b5c283c81532a3d605425

# Check for recent changes: https://github.com/openresty/luajit2/compare/v2.1-20230911...v2.1-agentzh
export LUAJIT_VERSION=2.1-20230911

# Check for recent changes: https://github.com/openresty/lua-resty-balancer/compare/v0.05...master
export LUA_RESTY_BALANCER=0.05

# Check for recent changes: https://github.com/openresty/lua-resty-lrucache/compare/52f5d00403c8b7aa8a4d4f3779681976b10a18c1...master
export LUA_RESTY_CACHE=52f5d00403c8b7aa8a4d4f3779681976b10a18c1

# Check for recent changes: https://github.com/openresty/lua-resty-core/compare/f75eec9ef44ea8732ecd7e6a0c2b2a73038e4b50...master
export LUA_RESTY_CORE=f75eec9ef44ea8732ecd7e6a0c2b2a73038e4b50

# Check for recent changes: https://github.com/cloudflare/lua-resty-cookie/compare/f418d77082eaef48331302e84330488fdc810ef4...master
export LUA_RESTY_COOKIE_VERSION=f418d77082eaef48331302e84330488fdc810ef4

# Check for recent changes: https://github.com/openresty/lua-resty-dns/compare/273db4f348d4676f554c5319a902e7b836153192...master
export LUA_RESTY_DNS=273db4f348d4676f554c5319a902e7b836153192

# Check for recent changes: https://github.com/ledgetech/lua-resty-http/compare/0ce55d6d15da140ecc5966fa848204c6fd9074e8...master
export LUA_RESTY_HTTP=0ce55d6d15da140ecc5966fa848204c6fd9074e8

# Check for recent changes: https://github.com/openresty/lua-resty-lock/compare/88a5886956af899e4277c6cdcd0d5b8f00a5093d...master
export LUA_RESTY_LOCK=88a5886956af899e4277c6cdcd0d5b8f00a5093d

# Check for recent changes: https://github.com/openresty/lua-resty-upload/compare/32b5b311bbbcfb474e3315bf74388d760dc2b697...master
export LUA_RESTY_UPLOAD_VERSION=32b5b311bbbcfb474e3315bf74388d760dc2b697

# Check for recent changes: https://github.com/openresty/lua-resty-string/compare/e6b80ac31dd9ff26bf444e50f5d7bda1089f972b...master
export LUA_RESTY_STRING_VERSION=e6b80ac31dd9ff26bf444e50f5d7bda1089f972b

# Check for recent changes: https://github.com/openresty/lua-resty-memcached/compare/f38de8bccb48f4dc0f683054efd68dc6d07468f6...master
export LUA_RESTY_MEMCACHED_VERSION=f38de8bccb48f4dc0f683054efd68dc6d07468f6

# Check for recent changes: https://github.com/openresty/lua-resty-redis/compare/b9e6f01f031cbec2a1f95c75dc97e1683cf2bbbd...master
export LUA_RESTY_REDIS_VERSION=b9e6f01f031cbec2a1f95c75dc97e1683cf2bbbd

# Check for recent changes: https://github.com/api7/lua-resty-ipmatcher/compare/v0.6.1...master
export LUA_RESTY_IPMATCHER_VERSION=0.6.1

# Check for recent changes: https://github.com/ElvinEfendi/lua-resty-global-throttle/compare/v0.2.0...main
export LUA_RESTY_GLOBAL_THROTTLE_VERSION=0.2.0

# Check for recent changes:  https://github.com/microsoft/mimalloc/compare/v1.8.2...master
export MIMALOC_VERSION=1.8.2

export BUILD_PATH=/tmp/build

ARCH=$(uname -m)

INVALID_CHECKSUM=0

get_src()
{
  hash="$1"
  url="$2"
  f=$(basename "$url")

  echo "Downloading $url"

  curl -4 -sSL "$url" -o "$f" || exit 10
  echo "Checking checksum $hash for $f - $(sha256sum "$f")"
  echo "$hash  $f" | sha256sum -c - || exit 10
  tar xzf "$f"
  rm -rf "$f"
}

# install required packages to build
apk add \
  bash \
  gcc \
  clang \
  libc-dev \
  make \
  automake \
  openssl-dev \
  pcre-dev \
  zlib-dev \
  linux-headers \
  libxslt-dev \
  gd-dev \
  perl-dev \
  libedit-dev \
  mercurial \
  alpine-sdk \
  findutils \
  curl \
  ca-certificates \
  patch \
  libaio-dev \
  openssl \
  cmake \
  util-linux \
  lmdb-tools \
  wget \
  curl-dev \
  libprotobuf \
  git g++ pkgconf flex bison doxygen yajl-dev lmdb-dev libtool autoconf libxml2 libxml2-dev \
  python3 \
  libmaxminddb-dev \
  bc \
  unzip \
  dos2unix \
  yaml-cpp \
  coreutils

mkdir -p /etc/nginx

mkdir --verbose -p "$BUILD_PATH"
cd "$BUILD_PATH"

# download, verify and extract the source files
get_src 05dd6d9356d66a74e61035f2a42162f8c754c97cf1ba64e7a801ba158d6c0711 \
        "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"

get_src aa961eafb8317e0eb8da37eb6e2c9ff42267edd18b56947384e719b85188f58b \
        "https://github.com/vision5/ngx_devel_kit/archive/v$NDK_VERSION.tar.gz"

get_src cd5e2cc834bcfa30149e7511f2b5a2183baf0b70dc091af717a89a64e44a2985 \
        "https://github.com/openresty/set-misc-nginx-module/archive/v$SETMISC_VERSION.tar.gz"

get_src 434cdf0bfe8342193a30dd45eafc13d9d4f4679aa023f612abb416e9069a9fc4 \
        "https://github.com/openresty/headers-more-nginx-module/archive/$MORE_HEADERS_VERSION.tar.gz"

get_src f09851e6309560a8ff3e901548405066c83f1f6ff88aa7171e0763bd9514762b \
        "https://github.com/atomx/nginx-http-auth-digest/archive/v$NGINX_DIGEST_AUTH.tar.gz"

get_src 32a42256616cc674dca24c8654397390adff15b888b77eb74e0687f023c8751b \
        "https://github.com/SpiderLabs/ModSecurity-nginx/archive/v$MODSECURITY_VERSION.tar.gz"

get_src bc764db42830aeaf74755754b900253c233ad57498debe7a441cee2c6f4b07c2 \
        "https://github.com/openresty/lua-nginx-module/archive/v$LUA_NGX_VERSION.tar.gz"

get_src 01b715754a8248cc7228e0c8f97f7488ae429d90208de0481394e35d24cef32f \
        "https://github.com/openresty/stream-lua-nginx-module/archive/v$LUA_STREAM_NGX_VERSION.tar.gz"

get_src e0baff472e1e8820d355701890f0c075ea0f0ba4ba6ca975f896912ae3b815c2 \
        "https://github.com/openresty/lua-upstream-nginx-module/archive/$LUA_UPSTREAM_VERSION.tar.gz"

get_src d08c23a0c793261cad1775795f258ca2149642eb19d3679a6bbb77582fa1d206 \
        "https://github.com/openresty/luajit2/archive/v$LUAJIT_VERSION.tar.gz"

get_src b6c9c09fd43eb34a71e706ad780b2ead26549a9a9f59280fe558f5b7b980b7c6 \
        "https://github.com/leev/ngx_http_geoip2_module/archive/$GEOIP2_VERSION.tar.gz"

get_src 0485c8009f45d9a9d74037e044413457a1ff1cab14030835ac99c47018858f58 \
        "https://github.com/openresty/lua-resty-upload/archive/$LUA_RESTY_UPLOAD_VERSION.tar.gz"

get_src aed7256e4605fa1974e7fcfccd3071d47429875667f33af77311b677db33b042 \
        "https://github.com/openresty/lua-resty-string/archive/$LUA_RESTY_STRING_VERSION.tar.gz"

get_src 8b2ff4edefc240dea0d3adb9dd065a42e8c09e06ba8bb0a188464cf76c9e4d06 \
        "https://github.com/openresty/lua-resty-balancer/archive/v$LUA_RESTY_BALANCER.tar.gz"

get_src 52195b23b96cdcc3556e5abd0a0089c6bf7fd9d3e3f06b9edcd4108dd734fb45 \
        "https://github.com/openresty/lua-resty-core/archive/$LUA_RESTY_CORE.tar.gz"

get_src 97daf9b1626c30abac3cfa8160c88e0e95d0aac33dc5eafbd27fe507fbd86499 \
        "https://github.com/openresty/lua-cjson/archive/$LUA_CJSON_VERSION.tar.gz"

get_src c0217456f4c36bb9ebbf7dbcd733e3d70734330364c88df73e703c4777521ff9 \
        "https://github.com/cloudflare/lua-resty-cookie/archive/$LUA_RESTY_COOKIE_VERSION.tar.gz"

get_src a72f343d91da876983daf5ea135dee4708424f02249c0c3ebc7c41a294d2dee1 \
        "https://github.com/openresty/lua-resty-lrucache/archive/$LUA_RESTY_CACHE.tar.gz"

get_src 8cf88eaf0eee4d03addf12c30368ef577dcef0bb14e51985aa3e2200a4f21344 \
        "https://github.com/openresty/lua-resty-lock/archive/$LUA_RESTY_LOCK.tar.gz"

get_src c54e72df8d8257da38d0e2d6d8065895fb172c0e30a100a5887166a952052355 \
        "https://github.com/openresty/lua-resty-dns/archive/$LUA_RESTY_DNS.tar.gz"

get_src 9fcb6db95bc37b6fce77d3b3dc740d593f9d90dce0369b405eb04844d56ac43f \
        "https://github.com/ledgetech/lua-resty-http/archive/$LUA_RESTY_HTTP.tar.gz"

get_src 5954d2702bd0054d61176a94f90621a0e5b29da6415d152c387a9292df3be7bc \
        "https://github.com/openresty/lua-resty-memcached/archive/$LUA_RESTY_MEMCACHED_VERSION.tar.gz"

get_src 304493fff4b255c4b22e8a52bd74d0d29ff014c8e7dd7d4bc6f68db0e79f6405 \
        "https://github.com/openresty/lua-resty-redis/archive/$LUA_RESTY_REDIS_VERSION.tar.gz"

get_src efb767487ea3f6031577b9b224467ddbda2ad51a41c5867a47582d4ad85d609e \
        "https://github.com/api7/lua-resty-ipmatcher/archive/v$LUA_RESTY_IPMATCHER_VERSION.tar.gz"

get_src 0fb790e394510e73fdba1492e576aaec0b8ee9ef08e3e821ce253a07719cf7ea \
        "https://github.com/ElvinEfendi/lua-resty-global-throttle/archive/v$LUA_RESTY_GLOBAL_THROTTLE_VERSION.tar.gz"

get_src 4058d53d6ceb75862f32c30a6ee686c3cbb5e965b2c324b828ca454f7fe064f9 \
        "https://github.com/microsoft/mimalloc/archive/refs/tags/v${MIMALOC_VERSION}.tar.gz"

# improve compilation times
CORES=$(($(grep -c ^processor /proc/cpuinfo) - 1))

export MAKEFLAGS=-j${CORES}
export CTEST_BUILD_FLAGS=${MAKEFLAGS}

# Install luajit from openresty fork
export LUAJIT_LIB=/usr/local/lib
export LUA_LIB_DIR="$LUAJIT_LIB/lua"
export LUAJIT_INC=/usr/local/include/luajit-2.1

cd "$BUILD_PATH/luajit2-$LUAJIT_VERSION"
make CCDEBUG=-g
make install

ln -s /usr/local/bin/luajit /usr/local/bin/lua
ln -s "$LUAJIT_INC" /usr/local/include/lua

cd "$BUILD_PATH"

# Git tuning
git config --global --add core.compression -1

# Get Brotli source and deps
cd "$BUILD_PATH"
git clone --depth=100 https://github.com/google/ngx_brotli.git
cd ngx_brotli
# https://github.com/google/ngx_brotli/issues/156
git reset --hard 63ca02abdcf79c9e788d2eedcc388d2335902e52
git submodule init
git submodule update

cd "$BUILD_PATH"
git clone --depth=1 https://github.com/ssdeep-project/ssdeep
cd ssdeep/

./bootstrap
./configure

make
make install

# build modsecurity library
cd "$BUILD_PATH"
git clone -n https://github.com/SpiderLabs/ModSecurity
cd ModSecurity/
git checkout $MODSECURITY_LIB_VERSION
git submodule init
git submodule update

sh build.sh

# https://github.com/SpiderLabs/ModSecurity/issues/1909#issuecomment-465926762
sed -i '115i LUA_CFLAGS="${LUA_CFLAGS} -DWITH_LUA_JIT_2_1"' build/lua.m4
sed -i '117i AC_SUBST(LUA_CFLAGS)' build/lua.m4

./configure \
  --disable-doxygen-doc \
  --disable-doxygen-html \
  --disable-examples

make
make install

mkdir -p /etc/nginx/modsecurity
cp modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf
cp unicode.mapping /etc/nginx/modsecurity/unicode.mapping

# Replace serial logging with concurrent
sed -i 's|SecAuditLogType Serial|SecAuditLogType Concurrent|g' /etc/nginx/modsecurity/modsecurity.conf

# Concurrent logging implies the log is stored in several files
echo "SecAuditLogStorageDir /var/log/audit/" >> /etc/nginx/modsecurity/modsecurity.conf

# Download owasp modsecurity crs
cd /etc/nginx/

git clone -b $OWASP_MODSECURITY_CRS_VERSION https://github.com/coreruleset/coreruleset
mv coreruleset owasp-modsecurity-crs
cd owasp-modsecurity-crs

mv crs-setup.conf.example crs-setup.conf
mv rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
mv rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
cd ..

# OWASP CRS v3 rules
echo "
Include /etc/nginx/owasp-modsecurity-crs/crs-setup.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-910-IP-REPUTATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-912-DOS-PROTECTION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-934-APPLICATION-ATTACK-NODEJS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-950-DATA-LEAKAGES.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-980-CORRELATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
" > /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf

# build nginx
cd "$BUILD_PATH/nginx-$NGINX_VERSION"

# apply nginx patches
for PATCH in `ls /patches`;do
  echo "Patch: $PATCH"
  if [[ "$PATCH" == *.txt ]]; then
    patch -p0 < /patches/$PATCH
  else
    patch -p1 < /patches/$PATCH
  fi
done

WITH_FLAGS="--with-debug \
  --with-compat \
  --with-pcre-jit \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_realip_module \
  --with-http_auth_request_module \
  --with-http_addition_module \
  --with-http_gzip_static_module \
  --with-http_sub_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_realip_module \
  --with-stream_ssl_preread_module \
  --with-threads \
  --with-http_secure_link_module \
  --with-http_gunzip_module"

# "Combining -flto with -g is currently experimental and expected to produce unexpected results."
# https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
CC_OPT="-g -O2 -fPIE -fstack-protector-strong \
  -Wformat \
  -Werror=format-security \
  -Wno-deprecated-declarations \
  -fno-strict-aliasing \
  -D_FORTIFY_SOURCE=2 \
  --param=ssp-buffer-size=4 \
  -DTCP_FASTOPEN=23 \
  -fPIC \
  -Wno-cast-function-type"

LD_OPT="-fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now"

if [[ ${ARCH} != "aarch64" ]]; then
  WITH_FLAGS+=" --with-file-aio"
fi

if [[ ${ARCH} == "x86_64" ]]; then
  CC_OPT+=' -m64 -mtune=generic'
fi

WITH_MODULES=" \
  --add-module=$BUILD_PATH/ngx_devel_kit-$NDK_VERSION \
  --add-module=$BUILD_PATH/set-misc-nginx-module-$SETMISC_VERSION \
  --add-module=$BUILD_PATH/headers-more-nginx-module-$MORE_HEADERS_VERSION \
  --add-module=$BUILD_PATH/lua-nginx-module-$LUA_NGX_VERSION \
  --add-module=$BUILD_PATH/stream-lua-nginx-module-$LUA_STREAM_NGX_VERSION \
  --add-module=$BUILD_PATH/lua-upstream-nginx-module-$LUA_UPSTREAM_VERSION \
  --add-dynamic-module=$BUILD_PATH/nginx-http-auth-digest-$NGINX_DIGEST_AUTH \
  --add-dynamic-module=$BUILD_PATH/ModSecurity-nginx-$MODSECURITY_VERSION \
  --add-dynamic-module=$BUILD_PATH/ngx_http_geoip2_module-${GEOIP2_VERSION} \
  --add-dynamic-module=$BUILD_PATH/ngx_brotli"

./configure \
  --prefix=/usr/local/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --modules-path=/etc/nginx/modules \
  --http-log-path=/var/log/nginx/access.log \
  --error-log-path=/var/log/nginx/error.log \
  --lock-path=/var/lock/nginx.lock \
  --pid-path=/run/nginx.pid \
  --http-client-body-temp-path=/var/lib/nginx/body \
  --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
  --http-proxy-temp-path=/var/lib/nginx/proxy \
  --http-scgi-temp-path=/var/lib/nginx/scgi \
  --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
  ${WITH_FLAGS} \
  --without-mail_pop3_module \
  --without-mail_smtp_module \
  --without-mail_imap_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module \
  --with-cc-opt="${CC_OPT}" \
  --with-ld-opt="${LD_OPT}" \
  --user=www-data \
  --group=www-data \
  ${WITH_MODULES}

make
make modules
make install

cd "$BUILD_PATH/lua-resty-core-$LUA_RESTY_CORE"
make install

cd "$BUILD_PATH/lua-resty-balancer-$LUA_RESTY_BALANCER"
make all
make install

export LUA_INCLUDE_DIR=/usr/local/include/luajit-2.1
ln -s $LUA_INCLUDE_DIR /usr/include/lua5.1

cd "$BUILD_PATH/lua-cjson-$LUA_CJSON_VERSION"
make all
make install

cd "$BUILD_PATH/lua-resty-cookie-$LUA_RESTY_COOKIE_VERSION"
make all
make install

cd "$BUILD_PATH/lua-resty-lrucache-$LUA_RESTY_CACHE"
make install

cd "$BUILD_PATH/lua-resty-dns-$LUA_RESTY_DNS"
make install

cd "$BUILD_PATH/lua-resty-lock-$LUA_RESTY_LOCK"
make install

# required for OCSP verification
cd "$BUILD_PATH/lua-resty-http-$LUA_RESTY_HTTP"
make install

cd "$BUILD_PATH/lua-resty-upload-$LUA_RESTY_UPLOAD_VERSION"
make install

cd "$BUILD_PATH/lua-resty-string-$LUA_RESTY_STRING_VERSION"
make install

cd "$BUILD_PATH/lua-resty-memcached-$LUA_RESTY_MEMCACHED_VERSION"
make install

cd "$BUILD_PATH/lua-resty-redis-$LUA_RESTY_REDIS_VERSION"
make install

cd "$BUILD_PATH/lua-resty-ipmatcher-$LUA_RESTY_IPMATCHER_VERSION"
INST_LUADIR=/usr/local/lib/lua make install

cd "$BUILD_PATH/lua-resty-global-throttle-$LUA_RESTY_GLOBAL_THROTTLE_VERSION"
make install

cd "$BUILD_PATH/mimalloc-$MIMALOC_VERSION"
mkdir -p out/release
cd out/release

cmake ../..

make
make install

# update image permissions
writeDirs=( \
  /etc/nginx \
  /usr/local/nginx \
  /opt/modsecurity/var/log \
  /opt/modsecurity/var/upload \
  /opt/modsecurity/var/audit \
  /var/log/audit \
  /var/log/nginx \
);

adduser -S -D -H -u 101 -h /usr/local/nginx -s /sbin/nologin -G www-data -g www-data www-data

for dir in "${writeDirs[@]}"; do
  mkdir -p ${dir};
  chown -R www-data.www-data ${dir};
done

rm -rf /etc/nginx/owasp-modsecurity-crs/.git
rm -rf /etc/nginx/owasp-modsecurity-crs/util/regression-tests

# remove .a files
find /usr/local -name "*.a" -print | xargs /bin/rm

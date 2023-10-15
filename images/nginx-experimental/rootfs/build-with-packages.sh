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

set -x

# Check for recent changes: https://github.com/atomx/nginx-http-auth-digest/compare/v1.0.0...atomx:master
export NGINX_DIGEST_AUTH=1.0.0

# Check for recent changes: https://github.com/SpiderLabs/ModSecurity-nginx/compare/v1.0.3...master
export MODSECURITY_VERSION=1.0.3

# Check for recent changes: https://github.com/SpiderLabs/ModSecurity/compare/v3.0.8...v3/master
export MODSECURITY_LIB_VERSION=e9a7ba4a60be48f761e0328c6dfcc668d70e35a0

# Check for recent changes: https://github.com/coreruleset/coreruleset/compare/v3.3.2...v3.3/master
export OWASP_MODSECURITY_CRS_VERSION=v3.3.5

# Check for recent changes: https://github.com/openresty/stream-lua-nginx-module/compare/v0.0.13...master
export LUA_STREAM_NGX_VERSION=0.0.13

# Check for recent changes: https://github.com/openresty/lua-cjson/compare/2.1.0.12...openresty:master
export LUA_CJSON_VERSION=2.1.0.12

# Check for recent changes: https://github.com/openresty/lua-resty-balancer/compare/v0.05...master
export LUA_RESTY_BALANCER=0.05

# Check for recent changes: https://github.com/cloudflare/lua-resty-cookie/compare/f418d77082eaef48331302e84330488fdc810ef4...master
export LUA_RESTY_COOKIE_VERSION=f418d77082eaef48331302e84330488fdc810ef4

# Check for recent changes: https://github.com/openresty/lua-resty-dns/compare/273db4f348d4676f554c5319a902e7b836153192...master
export LUA_RESTY_DNS=273db4f348d4676f554c5319a902e7b836153192

# Check for recent changes: https://github.com/openresty/lua-resty-upload/compare/32b5b311bbbcfb474e3315bf74388d760dc2b697...master
export LUA_RESTY_UPLOAD_VERSION=32b5b311bbbcfb474e3315bf74388d760dc2b697

# Check for recent changes: https://github.com/openresty/lua-resty-memcached/compare/f38de8bccb48f4dc0f683054efd68dc6d07468f6...master
export LUA_RESTY_MEMCACHED_VERSION=f38de8bccb48f4dc0f683054efd68dc6d07468f6

# Check for recent changes: https://github.com/openresty/lua-resty-redis/compare/b9e6f01f031cbec2a1f95c75dc97e1683cf2bbbd...master
export LUA_RESTY_REDIS_VERSION=b9e6f01f031cbec2a1f95c75dc97e1683cf2bbbd

# Check for recent changes: https://github.com/api7/lua-resty-ipmatcher/compare/v0.6.1...master
export LUA_RESTY_IPMATCHER_VERSION=0.6.1

# Check for recent changes: https://github.com/ElvinEfendi/lua-resty-global-throttle/compare/v0.2.0...main
export LUA_RESTY_GLOBAL_THROTTLE_VERSION=0.2.0

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
  coreutils \
  luajit-dev

mkdir -p /etc/nginx

mkdir --verbose -p "$BUILD_PATH"
cd "$BUILD_PATH"

get_src f09851e6309560a8ff3e901548405066c83f1f6ff88aa7171e0763bd9514762b \
        "https://github.com/atomx/nginx-http-auth-digest/archive/v$NGINX_DIGEST_AUTH.tar.gz"

get_src 32a42256616cc674dca24c8654397390adff15b888b77eb74e0687f023c8751b \
        "https://github.com/SpiderLabs/ModSecurity-nginx/archive/v$MODSECURITY_VERSION.tar.gz"

get_src 01b715754a8248cc7228e0c8f97f7488ae429d90208de0481394e35d24cef32f \
        "https://github.com/openresty/stream-lua-nginx-module/archive/v$LUA_STREAM_NGX_VERSION.tar.gz"

get_src 8b2ff4edefc240dea0d3adb9dd065a42e8c09e06ba8bb0a188464cf76c9e4d06 \
        "https://github.com/openresty/lua-resty-balancer/archive/v$LUA_RESTY_BALANCER.tar.gz"

get_src 97daf9b1626c30abac3cfa8160c88e0e95d0aac33dc5eafbd27fe507fbd86499 \
        "https://github.com/openresty/lua-cjson/archive/$LUA_CJSON_VERSION.tar.gz"

get_src c0217456f4c36bb9ebbf7dbcd733e3d70734330364c88df73e703c4777521ff9 \
        "https://github.com/cloudflare/lua-resty-cookie/archive/$LUA_RESTY_COOKIE_VERSION.tar.gz"

get_src c54e72df8d8257da38d0e2d6d8065895fb172c0e30a100a5887166a952052355 \
        "https://github.com/openresty/lua-resty-dns/archive/$LUA_RESTY_DNS.tar.gz"

get_src 0485c8009f45d9a9d74037e044413457a1ff1cab14030835ac99c47018858f58 \
        "https://github.com/openresty/lua-resty-upload/archive/$LUA_RESTY_UPLOAD_VERSION.tar.gz"

get_src 5954d2702bd0054d61176a94f90621a0e5b29da6415d152c387a9292df3be7bc \
        "https://github.com/openresty/lua-resty-memcached/archive/$LUA_RESTY_MEMCACHED_VERSION.tar.gz"

get_src 304493fff4b255c4b22e8a52bd74d0d29ff014c8e7dd7d4bc6f68db0e79f6405 \
        "https://github.com/openresty/lua-resty-redis/archive/$LUA_RESTY_REDIS_VERSION.tar.gz"

get_src efb767487ea3f6031577b9b224467ddbda2ad51a41c5867a47582d4ad85d609e \
        "https://github.com/api7/lua-resty-ipmatcher/archive/v$LUA_RESTY_IPMATCHER_VERSION.tar.gz"

get_src 0fb790e394510e73fdba1492e576aaec0b8ee9ef08e3e821ce253a07719cf7ea \
        "https://github.com/ElvinEfendi/lua-resty-global-throttle/archive/v$LUA_RESTY_GLOBAL_THROTTLE_VERSION.tar.gz"

# improve compilation times
CORES=$(($(grep -c ^processor /proc/cpuinfo) - 1))

export MAKEFLAGS=-j${CORES}
export CTEST_BUILD_FLAGS=${MAKEFLAGS}

cd "$BUILD_PATH"

# Git tuning
git config --global --add core.compression -1

export LUA_INCLUDE_DIR=/usr/include/luajit-2.1
ln -s $LUA_INCLUDE_DIR /usr/include/lua5.1

cd "$BUILD_PATH/lua-resty-balancer-$LUA_RESTY_BALANCER"
make all
make install

cd "$BUILD_PATH/lua-cjson-$LUA_CJSON_VERSION"
make all
make install

cd "$BUILD_PATH/lua-resty-cookie-$LUA_RESTY_COOKIE_VERSION"
make all
make install

cd "$BUILD_PATH/lua-resty-dns-$LUA_RESTY_DNS"
make install

cd "$BUILD_PATH/lua-resty-upload-$LUA_RESTY_UPLOAD_VERSION"
make install

cd "$BUILD_PATH/lua-resty-memcached-$LUA_RESTY_MEMCACHED_VERSION"
make install

cd "$BUILD_PATH/lua-resty-redis-$LUA_RESTY_REDIS_VERSION"
make install

cd "$BUILD_PATH/lua-resty-ipmatcher-$LUA_RESTY_IPMATCHER_VERSION"
INST_LUADIR=/usr/local/lib/lua make install

cd "$BUILD_PATH/lua-resty-global-throttle-$LUA_RESTY_GLOBAL_THROTTLE_VERSION"
make install

# build modsecurity library
cd "$BUILD_PATH"
git clone -n https://github.com/SpiderLabs/ModSecurity
cd ModSecurity/
git checkout $MODSECURITY_LIB_VERSION
git submodule init
git submodule update

sh build.sh

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

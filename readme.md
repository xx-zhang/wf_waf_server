# workflow + modsecurity 打造软waf
- http server waf and modsecurity backend 



## install guide 
```bash

#https://github.com/owasp-modsecurity/ModSecurity/wiki/Compilation-recipes-for-v3.x#centos-7-minimal

yum install gcc-c++ flex bison yajl yajl-devel curl-devel curl GeoIP-devel doxygen zlib-devel pcre-devel
cd /opt/
git clone https://github.com/owasp-modsecurity/ModSecurity
cd ModSecurity
git checkout -b v3/master origin/v3/master
sh build.sh
git submodule init
git submodule update
./configure
yum install https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/23/x86_64/b/bison-3.0.4-3.fc23.x86_64.rpm
make -j$(nproc)
make install

```

## build 2024.12.12 
>  g++ ./httplib_waf.cpp -I ../contrib/include/  -I /usr/local/modsecurity/include/ -L /usr/local/modsecurity/lib/ -std=c++11  -lpthread -std=c++17 -lmodsecurity -O3 -g 

我们用 httplib-cpp 是可以的； 但是使用 workflow就不行了。


## build 2025.1.1  ERROR [workflow]

>  g++ ./main.cpp -I /usr/local/modsecurity/include/ -L /usr/local/modsecurity/lib/ -lworkflow -std=c++11  -lpthread -std=c++17 -lmodsecurity -O3 -g 

```
Reading symbols from ./a.out...
(gdb) run 
Starting program: /opt/wf_waf_server/src/a.out 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff72304c0 in std::ostream::sentry::sentry(std::ostream&) () from /lib64/libstdc++.so.6
Missing separate debuginfos, use: dnf debuginfo-install GeoIP-1.6.12-7.el8.x86_64 brotli-1.0.6-3.tl3.x86_64 cyrus-sasl-lib-2.1.27-6.tl3.x86_64 keyutils-libs-1.5.10-9.tl3.x86_64 krb5-libs-1.18.2-27.tl3.x86_64 libcom_err-1.45.6-5.tl3.x86_64 libcurl-7.61.1-34.tl3.2.x86_64 libgcc-8.5.0-23.tl3.1.x86_64 libidn2-2.2.0-1.tl3.x86_64 libnghttp2-1.33.0-5.tl3.x86_64 libpsl-0.20.2-6.tl3.x86_64 libssh-0.9.6-14.tl3.x86_64 libstdc++-8.5.0-23.tl3.1.x86_64 libunistring-0.9.9-3.tl3.1.x86_64 libxcrypt-4.1.1-6.tl3.x86_64 lua-libs-5.3.4-12.tl3.x86_64 openldap-2.4.46-18.tl3.x86_64 pcre-8.42-6.tl3.x86_64 pcre2-10.32-3.tl3.x86_64 yajl-2.1.0-12.tl3.x86_64
(gdb) 
```

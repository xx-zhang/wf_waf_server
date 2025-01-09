# workflow + modsecurity 打造软waf
-



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

```
        "-I/usr/local/modsecurity/include/",
```


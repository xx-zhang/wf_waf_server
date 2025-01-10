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

## build 2024.12.24 transcation非独立事务时OK 
>  g++ ./wf_waf.cpp -I /usr/local/modsecurity/include/ -L /usr/local/modsecurity/lib/ -lworkflow -lpthread -std=c++17 -lmodsecurity -O3 -g -o a.elf 


## build 2025.1.1  ERROR [workflow]
- 把 transcation 作为独立事务拿出来时候就不能OK了。 

>  g++ ./main.cpp -I /usr/local/modsecurity/include/ -L /usr/local/modsecurity/lib/ -lworkflow -std=c++11  -lpthread -std=c++17 -lmodsecurity -O3 -g 


# BUG
## bug 2025.1.6 
- 当前遇到问题 modsecurity parse all http error.


# libexif


## environment
OS: ubuntu20.04LTS
LLVM: 11
afl++: latest  
libexif: 0.6.18

## 编译libexif
```sh
export LLVM_CONFIG="llvm-config-11"
CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

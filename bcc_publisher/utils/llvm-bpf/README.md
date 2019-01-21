# Prerequisites
Export the following variables. Please note that the system should have already been initialized with `make sysprep`.

```
export CC="/usr/local/osquery/bin/clang"
export CXX="/usr/local/osquery/bin/clang++"
export LD_LIBRARY_PATH="/usr/local/osquery/lib"
export LDFLAGS="-L/usr/local/osquery/legacy/lib -L/usr/local/osquery/lib -B/usr/local/osquery/legacy/lib -rtlib=compiler-rt -fuse-ld=lld"
```

1. `mkdir build && cd build`
2. `cmake ..`
3. `make init_llvm_source`
4. `cmake ..`
5. `make -j $(nproc)`
6. `make install`


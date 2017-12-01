## How to build the extensions
1. Symlink the extensions you intend to build into the external osquery directory. Use the following link name: "extension_\<name\>".
2. Build osquery
3. Run 'make externals'

## Example
```
ln -s efigy /src/osquery/external/extension_efigy

cd /src/osquery
make sysprep
make deps

make -j `nproc`
make externals
```


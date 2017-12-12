## How to build the extensions
1. Clone the osquery repository
2. Symlink the extensions you intend to build into the external osquery directory. Use the following link name: "extension_\<name\>".
3. Build osquery
4. Run 'make externals'

## Example
```
cd /src
git clone https://github.com/facebook/osquery.git

cd /src/osquery-extensions
ln -s efigy /src/osquery/external/extension_efigy

cd /src/osquery
make sysprep
make deps

make -j `nproc`
make externals
```


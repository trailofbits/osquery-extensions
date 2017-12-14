# Trail of Bits osquery Extensions

This is a repository includes [osquery](https://osquery.io/) [extensions](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/) developed and maintained by Trail of Bits.

## Building

1. Clone the osquery repository
2. Symlink the extensions you intend to build into the external osquery directory. Use the following link name: "extension_\<name\>".
3. Build osquery
4. Run 'make externals'

### Example
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

## Usage

To quickly test the extension, you can either start it from the osqueryi shell, or launch it manually and wait for it to connect to the running osquery instance.

> osqueryi --extension /path/to/extension

See the [osquery documentation on extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions) for further information.

## Contributing

Do you have an idea for an osquery extension? Please [file an issue](https://github.com/trailofbits/osquery-extensions/issues/new) for it. We welcome contributions of bug fixes, feature requests, and extensions.

## License

The code within this repository is licensed under the [Apache 2.0 license](LICENSE).

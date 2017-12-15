# Trail of Bits osquery Extensions

This repository includes [osquery](https://osquery.io/) [extensions](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/) developed and maintained by [Trail of Bits](https://www.trailofbits.com/).

## Building

1. Clone the osquery repository
2. Symlink the extensions you want to build into the external osquery directory. Use the following link name: "extension_\<name\>".
3. Build osquery
4. Run 'make externals'

### Example

```
cd /src
git clone https://github.com/facebook/osquery.git
git clone https://github.com/trailofbits/osquery-extensions.git

cd /src/osquery-extensions
ln -s /src/osquery-extensions/efigy /src/osquery/external/extension_efigy

cd /src/osquery
make sysprep
make deps

make -j `nproc` # If using macOS, replace `nproc` with `sysctl -n hw.ncpu`
make externals

# Run make again to ensure osquery recognizes the extension to build
make -j `nproc`
```

If you see the following warning, it can be ignored: `-- Cannot find Doxygen executable in path`

The extension should be in a subfolder of `/src/osquery/build` once the second make command completes successfully. Using `find . -name "efigy.ext"` can help you locate it quickly.

## Usage

To quickly test an extension, you can either start it from the osqueryi shell, or launch it manually and wait for it to connect to the running osquery instance.

Consider either changing the ownership of `efigy.ext` to root or running osquery with the `--allow_unsafe` flag.

> osqueryi --extension /path/to/efigy.ext

```
$ sudo osqueryi --extension osquery-facebook/build/darwin10.12/external/extension_efigy/efigy.ext
Using a virtual database. Need help, type '.help'
osquery> select * from efigy;
+--------------------+-----------------+--------------------+-------------------+------------+---------------------+
| latest_efi_version | efi_version     | efi_version_status | latest_os_version | os_version | build_number_status |
+--------------------+-----------------+--------------------+-------------------+------------+---------------------+
| MBP142.0167.B00    | MBP142.0167.B00 | success            | 10.12.6           | 10.12.6    | success             |
+--------------------+-----------------+--------------------+-------------------+------------+---------------------+
osquery>
```

See the [osquery documentation on extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions) for further information.

## Contributing

Do you have an idea for an osquery extension? Please [file an issue](https://github.com/trailofbits/osquery-extensions/issues/new) for it. We welcome contributions of bug fixes, feature requests, and extensions.

## Troubleshooting

When troubleshooting, ensure you are running osqueryd/osqueryi with the `--verbose` flag.

* If you encounter the following error, you need change the owner of efigy.ext to be root or run osquery with the `--allow_unsafe` flag: `watcher.cpp:535] [Ref #1382] Extension binary has unsafe permissions:1`

## License

The code within this repository is licensed under the [Apache 2.0 license](LICENSE).

# EFIgy osquery extension

[EFIgy](http://efigy.io/) is a service by Duo Labs that helps Apple Mac users determine if they are running the expected EFI firmware version given their Mac hardware and OS build version. This extension integrates osquery with the EFIgy API, so you can determine if all of the EFI firmware on your Mac fleet is up-to-date.

## Dependencies

Requirements:
* macOS, user with sudo (to run the osquery build dependencies install script)
* Xcode
* openssl and curl (install from Homebrew: `brew install openssl curl`)

## Building

1. Clone the osquery repository
2. Symlink this extension into the external osquery directory. Use the following link name: "extension_santa".
3. Build osquery
4. Run 'make externals'

```
cd /src
git clone https://github.com/facebook/osquery.git
git clone https://github.com/trailofbits/osquery-extensions.git

cd /src/osquery-extensions
ln -s efigy /src/osquery/external/extension_efigy

cd /src/osquery
make sysprep
make deps

make -j `sysctl -n hw.ncpu` # how you parallelize the build when on macOS
make externals

# Run make again to ensure osquery recognizes the extension to build
make -j `sysctl -n hw.ncpu`
```

If you see the following warning, it can be ignored: `-- Cannot find Doxygen executable in path`

The extension should be in a subfolder of `/src/osquery/build` once the second make command completes successfully. 
Using `find . -name "efigy.ext"` can help you locate it quickly.

## Usage

To quickly test an extension, you can either start it from the osqueryi shell, or launch it manually and wait for it 
to connect to the running osquery instance.

Consider either changing the ownership of `efigy.ext` to root, or running osquery with the `--allow_unsafe` flag.

`osqueryi --extension /path/to/efigy.ext`
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

See the [osquery documentation on extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions) for further 
information.

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).

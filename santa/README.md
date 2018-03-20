# Santa osquery Extension

[Santa](https://github.com/google/santa/) is an open-source application whitelist/blacklist enforcement solution for macOS.
This extension for osquery enables the osquery user to read the log of `DENY` events that Santa generated on the host 
with a table called `santa_events`, and to remotely view and *create* new rules for Santa (with or without the use of a Santa sync 
server) with a table called `santa_rules`.

## Building

Requirements:
* Xcode
* Boost (can be installed with Homebrew: `brew install boost`)

1. Clone the osquery repository
2. Symlink this extension into the external osquery directory. Use the following link name: "extension_santa".
3. Build osquery
4. Run 'make externals'

```
cd /src
git clone https://github.com/facebook/osquery.git
git clone https://github.com/trailofbits/osquery-extensions.git

cd /src/osquery-extensions
ln -s /src/osquery-extensions/santa /src/osquery/external/extension_santa

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
Using `find . -name "santa.ext"` can help you locate it quickly.

## Usage

To quickly test an extension, you can either start it from the osqueryi shell, or launch it manually and wait for it 
to connect to the running osquery instance.

Consider either changing the ownership of `santa.ext` to root, or running osquery with the `--allow_unsafe` flag.

> osqueryi --extension /path/to/santa.ext

```
$ sudo ./build/darwin10.13/osquery/osqueryi --extension ./build/darwin10.13/external/extension_santa/santa.ext
Using a virtual database. Need help, type '.help'
osquery> .schema santa_rules
CREATE TABLE santa_rules(`shasum` TEXT, `state` TEXT, `type` TEXT);
osquery> .schema santa_events
CREATE TABLE santa_events(`timestamp` TEXT, `path` TEXT, `shasum` TEXT, `reason` TEXT);
```

See the [osquery documentation on extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions) for further 
information.

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).

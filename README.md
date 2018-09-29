# Trail of Bits osquery Extensions

This repository includes [osquery](https://osquery.io/) [extensions](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/) developed and maintained by [Trail of Bits](https://www.trailofbits.com/). If you would like to sponsor the development of an extension, [please contact us](https://www.trailofbits.com/contact/).

[Extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions/) are a type of osquery add-on that can be loaded at runtime to provide new virtual tables, with capabilities that go beyond the limitations of mainline osquery. Trail of Bits has developed extensions to provide tables that can _manage_ service configurations as well as _view_ them (currently pending the merge of [PR4094](https://github.com/facebook/osquery/pull/4094)), or that can cross-check information on the host with external third-party services. The extensions interface is commonly used to address individual organizations' needs, or to implement proprietary detection methods. Here we use it to demonstrate some pioneering use cases of osquery. To learn more, view our talk ([slides](https://github.com/trailofbits/presentations/tree/master/Osquery%20Extensions), [video](https://www.youtube.com/watch?v=g46rjoP18EE)) from QueryCon 2018.

| Extension            | Description | Supported Endpoints |
|          :-:         |    :-:      |         :-:         |
| efigy                | Integrates osquery with the Duo Labs EFIgy API to determine if the EFI firmware on your Mac fleet is up-to-date. | macOS |
| santa                | Integrates osquery with the Santa application whiteslisting solution. Check DENY events and manage the whitelist/blacklist rules. | macOS |
| fwctl                | Provides osquery with the ability to view and manage the OS-native firewall rules and `/etc/hosts` file (port and host blocking). | macOS, Linux, Windows |
| ntfs_forensics       | Provides osquery with NTFS-specific forensic information for incident responders. | Windows |
| windows_sync_objects | Provides osquery with the ability of listing and locking Windows synchronization objects (mutants, events, semaphores). | Windows |
| darwin_unified_log   | Provides an event driven table that contains entries from the unified system log on MacOS. | macOS | 
| (more to come)       | ...  | ...   |

## Dependencies

##### Boost library (all platforms)

The full Boost package is required to build the extensions. Unfortunately, the version provided with osquery does not yet come with all the Boost components.

We have already submitted the following PR to fix the issue: https://github.com/facebook/osquery/pull/4339

For the time being, it is best to cherry-pick the [commits from that branch](https://github.com/facebook/osquery/pull/4339/commits) over to your local osquery repository.

For Linux or macOS, this is enough, and will automatically take care of the Boost dependency for Linux and macOS. For Windows, you must **also** rebuild the Boost package from source (due to a bug in the binaries that were uploaded to the S3 repository). When doing this, you should work from a folder close to the root of the drive, like `C:\Projects\osquery`, because the Boost script will generate many nested folders, and often hits the path size limit and fails, a problem not very apparent to the Chocolatey package manager.

So, for Windows, after cloning the osquery repository and cherry-picking the commits as described, the remaining steps are:

1. Run the following script once: `.\tools\make-win64-dev-env.bat`
2. Uninstall the boost-msvc14 package that osquery's scripts just installed: `choco uninstall boost-msvc14`
3. Build the Boost package from source (at a Powershell prompt): `.\tools\provision\chocolatey\boost-msvc14.ps1`
4. Enter the folder where the package was created: `cd .\build\chocolatey\boost-msvc14\boost_1_66_0\osquery-choco`
5. Run `choco install -s . .\boost-msvc14.1.66.0-r2.nupkg` to install the Boost package you just built.

In case you want a binary package, we have uploaded one in the [releases](https://github.com/trailofbits/osquery-extensions/releases) page.

##### macOS

You will need to have:
* Xcode (installed from the App Store)
* [Homebrew](https://brew.sh)
* openssl and curl (install from Homebrew: `brew install openssl curl`)
* a user account with sudo (in order to run the script that installs the other osquery build dependencies)

## Building

At a high-level, the steps are:
1. Clone the osquery and osquery-extensions repositories
2. Symlink the osquery-extensions folder into `osquery/externals/external_trailofbits`
3. Run the osquery scripts to install dependencies and build osquery, which also builds the extensions

Here are example steps for each platform:

### Windows
```
cd \Projects
git clone https://github.com/facebook/osquery.git
git clone https://github.com/trailofbits/osquery-extensions.git

# Symbolically link the extensions repo into the osquery core repo:
mklink /D "\Projects\osquery\external\extension_trailofbits" "\Projects\osquery-extensions"

# From a shell with Administrator privileges:
cd \Projects\osquery
.\tools\make-win64-dev-env.bat
.\tools\make-win64-binaries.bat

# To additionally build the extensions, now:
cd build\windows10
cmake --build . --config Release --target trailofbits_osquery_extensions
```

### macOS or Linux
```
cd /src
git clone https://github.com/facebook/osquery.git
git clone https://github.com/trailofbits/osquery-extensions.git

cd /src/osquery
ln -s /src/osquery-extensions /src/osquery/external/extension_trailofbits

make sysprep
make deps

# If using macOS, replace `nproc` with `sysctl -n hw.ncpu`
make -j `nproc` 
```

If you see the following warning, it can be ignored: `-- Cannot find Doxygen executable in path`

It's also possible to select which extensions to build, using the TRAILOFBITS_EXTENSIONS_TO_BUILD environment variable and specifying a comma separated list of extension names.  
For example, if you wish to build both the windows_sync_objects and fwctl extensions on Windows, you can set it to:
```
$env:TRAILOFBITS_EXTENSIONS_TO_BUILD = "windows_sync_objects,fwctl"
```

This is where the extension should be available once it has been built:
 * Windows: `osquery/build/windows10/external/Release/trailofbits_osquery_extensions.ext.exe`
 * Linux: `osquery/build/linux/external/trailofbits_osquery_extensions.ext`
 * macOS: `osquery/build/darwin/external/trailofbits_osquery_extensions.ext`

## Running the automated tests

Once osquery has been built with tests enabled (i.e.: *without* the SKIP_TESTS variable), enter the build/<platform_name> folder and run the following command: `make trailofbits_extensions_tests`. Note that tests are not yet supported on Windows.

## Usage

To quickly test an extension, you can either start it from the osqueryi shell, or launch it manually and wait for it to connect to the running osquery instance.

By default, osquery does not want to load extensions not owned by root. You can either change the ownership of `trailofbits_osquery_extensions.ext` to root, or run osquery with the `--allow_unsafe` flag.

> osqueryi --extension /path/to/trailofbits_osquery_extensions.ext

```
$ sudo osqueryi --extension osquery/build/darwin/external/trailofbits_osquery_extensions.ext
Using a virtual database. Need help, type '.help'
osquery> SELECT * FROM efigy;
+--------------------+-----------------+--------------------+-------------------+------------+---------------------+
| latest_efi_version | efi_version     | efi_version_status | latest_os_version | os_version | build_number_status |
+--------------------+-----------------+--------------------+-------------------+------------+---------------------+
| MBP142.0167.B00    | MBP142.0167.B00 | success            | 10.12.6           | 10.12.6    | success             |
+--------------------+-----------------+--------------------+-------------------+------------+---------------------+
osquery>
```

See the [osquery documentation on extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions) for further information.

## Contributing

Do you have an idea for an osquery extension? Please [file an issue](https://github.com/trailofbits/osquery-extensions/issues/new) for it. We welcome contributions of bug fixes, bug reports, feature requests, and new extensions. For more information on how you can contribute, see our [Contributing Guidelines](https://github.com/trailofbits/osquery-extensions/blob/master/CONTRIBUTING.md).

## Troubleshooting

When troubleshooting, ensure you are running osqueryd/osqueryi with the `--verbose` flag.

* As mentioned, if you encounter the following error, you need change the owner of `trailofbits_osquery_extensions.ext` to be the root account, or else run osquery with the `--allow_unsafe` flag: `watcher.cpp:535] [Ref #1382] Extension binary has unsafe permissions:1`

## License

The code in this repository is licensed under the [Apache 2.0 license](LICENSE).

# Trail of Bits osquery Extensions

This repository includes [osquery](https://osquery.io/) [extensions](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/) developed and maintained by [Trail of Bits](https://www.trailofbits.com/). If you would like to sponsor the development of an extension, [please contact us](https://www.trailofbits.com/contact/).

[Extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions/) are a type of osquery add-on that can be loaded at runtime to provide new virtual tables. The extensions interface allows organizations to implement proprietary detection methods, or address their individual needs. Here, we use it to demonstrate other pioneering use cases of osquery.

In extensions, we can add capabilities that go beyond what would be possible in osquery core. Trail of Bits has developed extensions to provide tables that can _manage_ service configurations as well as _view_ them, or that can cross-check information on the host with external third-party services.

To learn more about osquery extensions development and why developing outside of 'core' is encouraged for demonstrating new use cases or novel functionality, view our talk ([slides](https://github.com/trailofbits/presentations/tree/master/Osquery%20Extensions), [video](https://www.youtube.com/watch?v=g46rjoP18EE)) from QueryCon 2018.

| Extension            | Description | Supported Endpoints |
|          :-:         |    :-:      |         :-:         |
| efigy                | Integrates osquery with the Duo Labs EFIgy API to determine if the EFI firmware on your Mac fleet is up-to-date. | macOS |
| santa                | Integrates osquery with the Santa application whitelisting solution. Check DENY events and manage the whitelist/blacklist rules. | macOS |
| fwctl                | Provides osquery with the ability to view and manage the OS-native firewall rules and `/etc/hosts` file (port and host blocking). | macOS, Linux, Windows |
| ntfs_forensics       | Provides osquery with NTFS-specific forensic information for incident responders. | Windows |
| windows_sync_objects | Provides osquery with the ability of listing and locking Windows synchronization objects (mutants, events, semaphores). | Windows |
| darwin_unified_log   | Provides an event driven table that contains entries from the unified system log on MacOS. | macOS |
| iptables             | Provides a superset of the information supplied by the default `iptables` table | Linux |
| (more to come)       | ...  | ...   |

Experimental extensions:
 * **network_monitor**: Provides an event-based table that lists DNS requests performed by the endpoint. Uses libpcap and Pcap++ to capture and parse network requests.

## Build Dependencies

Note: the [releases](https://github.com/trailofbits/osquery-extensions/releases) page has download links for our extensions. The instructions below are only necessary for those interested in building from source.

##### Boost library (all platforms)

The full Boost library is required to build the Trail of Bits osquery extensions. Unfortunately, the version of Boost that osquery core builds against does not currently include all of the necessary Boost components.

We've submitted a PR to osquery core, to fix the issue: https://github.com/facebook/osquery/pull/4339

For the time being, you can include the entire Boost library in the osquery core build by applying the [commits from that branch](https://github.com/facebook/osquery/pull/4339/commits) to your local copy of the osquery repository.

For Linux or macOS, you only need to apply the patch as follows, and nothing else is necessary to build the full Boost dependency for these operating systems:

```bash
# assuming you have checked out the osquery core code to './osquery'
cd osquery
curl https://patch-diff.githubusercontent.com/raw/facebook/osquery/pull/4339.patch | git am
```

Additional steps are required for Windows (see below).

##### macOS

You will additionally need to have:

- Xcode (installed from the App Store)
- [Homebrew](https://brew.sh)
- openssl and curl (install from Homebrew: `brew install openssl curl`)
- a user account with sudo (in order to run the script that installs the other osquery build dependencies)

##### Windows

For Windows only, you must also rebuild the Boost package from source (due to a bug in the binaries that were uploaded to the S3 repository). When doing this, you must work in a folder close to the root of the drive, like `C:\Projects\osquery`. This is because the Boost script will generate many nested folders, and often hits the path size limit and fails, a problem not very apparent to the Chocolatey package manager.

After cloning the osquery repository and cherry-picking the full set of [commits from the PR mentioned above](https://github.com/facebook/osquery/pull/4339/commits), the remaining steps are:

1. Run the following script once: `.\tools\make-win64-dev-env.bat`
2. Uninstall the boost-msvc14 package that osquery's scripts just installed: `choco uninstall boost-msvc14`
3. Build the Boost package from source (at a Powershell prompt): `.\tools\provision\chocolatey\boost-msvc14.ps1`
4. Enter the folder where the package was created: `cd .\build\chocolatey\boost-msvc14\boost_1_66_0\osquery-choco`
5. Run `choco install -s . .\boost-msvc14.1.66.0-r2.nupkg` to install the Boost package you just built.

Remember, if you'd just rather have a binary package, you'll find one in the [releases](https://github.com/trailofbits/osquery-extensions/releases) page.

## Building

At a high-level, the steps are:
1. Clone the osquery and osquery-extensions repositories
2. Symlink the osquery-extensions folder into `osquery/external/extension_trailofbits`
3. Run the osquery scripts to install dependencies and build osquery, which also builds the extensions

Additionally, the osquery-extensions repository has git submodules that need to be pulled.

Here are example steps for each platform:

### macOS or Linux

Note: Due to the current way `bison` is built, you may need to add some symlinks to your system. This is only necessary if you want to build the `network_monitor` extension, or are building all extensions.

```
/home/linuxbrew/.linuxbrew/Cellar -> /usr/local/osquery/Cellar
/home/linuxbrew/.linuxbrew/opt -> /usr/local/osquery/opt
```

Then you can run the following commands.

```
cd /src
git clone https://github.com/facebook/osquery.git
git clone https://github.com/trailofbits/osquery-extensions.git

cd /src/osquery-extensions
git submodule init
git submodule update --recursive

cd /src/osquery
ln -s /src/osquery-extensions /src/osquery/external/extension_trailofbits

make sysprep
make deps

# If using macOS, replace `nproc` with `sysctl -n hw.ncpu`
make -j `nproc`
```

### Windows
```
cd \Projects
git clone https://github.com/facebook/osquery.git
git clone https://github.com/trailofbits/osquery-extensions.git

cd \Projects\osquery-extensions
git submodule init
git submodule update --recursive

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

If you see the following warning, it can be ignored: `-- Cannot find Doxygen executable in path`

### Specifying the extensions to be built

By default, all of the extensions in our repository are built into one executable. It's also possible to select which extensions to build, using the `TRAILOFBITS_EXTENSIONS_TO_BUILD` environment variable and specifying a comma separated list of extension names. For example, if you wish to build both the `windows_sync_objects` and `fwctl` extensions on Windows, you can set it to:

```
$env:TRAILOFBITS_EXTENSIONS_TO_BUILD = "windows_sync_objects,fwctl"
```

### Finding the executable binary

This is where the extension should be available once it has been built:

 * Linux: `osquery/build/linux/external/trailofbits_osquery_extensions.ext`
 * macOS: `osquery/build/darwin/external/trailofbits_osquery_extensions.ext`
 * Windows: `osquery/build/windows10/external/Release/trailofbits_osquery_extensions.ext.exe`

## Running the automated tests

macOS or Linux: once osquery has been built with tests enabled (*i.e.*, *without* the `SKIP_TESTS` variable), enter the build/<platform_name> folder and run the following command: `make trailofbits_extensions_tests`.

Windows: tests are not yet supported on Windows.

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

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

## Building

Note: the [releases](https://github.com/trailofbits/osquery-extensions/releases) page has download links for our extensions. The instructions below are only necessary for those interested in building from source.

At a high-level, the steps are:
1. Follow the osquery guide at https://osquery.readthedocs.io/en/latest/development/building/
   to install pre-requisites and build but stop just before the configure step.
2. Clone the osquery-extensions repo.
3. Symlink the osquery-extensions folder into `osquery/external/extension_trailofbits`.
4. Resume following the osquery build guide to build osquery and now the extensions too.

Here are example steps for each platform:


### Linux/macOS

```
# Follow https://osquery.readthedocs.io/en/latest/development/building/
# and stop before the configure step
cd ../../
git clone --recurse-submodules https://github.com/trailofbits/osquery-extensions.git

cd osquery
ln -s ../../osquery-extensions osquery/external/extension_trailofbits

cd build
# Keep following the osquery guide
```

### Windows 10

```
# Follow https://osquery.readthedocs.io/en/latest/development/building/
# and stop before the configure step
cd ../../
git clone --recurse-submodules https://github.com/trailofbits/osquery-extensions.git

cd osquery
mklink /D ..\..\osquery-extensions osquery\external\extension_trailofbits

cd build
# Keep following the osquery guide
```

### Specifying the extensions to be built

By default, all of the extensions in our repository are built into one executable. It's also possible to select which extensions to build, using the `TRAILOFBITS_EXTENSIONS_TO_BUILD` environment variable and specifying a comma separated list of extension names. For example, if you wish to build both the `windows_sync_objects` and `fwctl` extensions on Windows, you can set it to:

```
$env:TRAILOFBITS_EXTENSIONS_TO_BUILD = "windows_sync_objects,fwctl"
```

### Finding the executable binary

This is where the extension should be available once it has been built:

 * Linux: `osquery/build/external/trailofbits_osquery_extensions.ext`
 * macOS: `osquery/build/external/trailofbits_osquery_extensions.ext`
 * Windows: `osquery/build/external/Release/trailofbits_osquery_extensions.ext.exe`

## Running the automated tests

macOS or Linux: once osquery has been built with tests enabled (*i.e.*, *with* `-DOSQUERY_BUILD_TESTS=ON` CMake option), enter the build folder and run the following command: `cmake --build . --target trailofbits_extensions_tests`.

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

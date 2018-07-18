# EFIgy osquery extension

[EFIgy](http://efigy.io/) is a service by Duo Labs that helps Apple Mac users determine if they are running the expected EFI firmware version given their Mac hardware and OS build version. This extension integrates osquery with the EFIgy API, so you can determine if all of the EFI firmware on your Mac fleet is up-to-date.

## Usage

To quickly test an extension, you can either start it from the osqueryi shell, or launch it manually and wait for it 
to connect to the running osquery instance.

Consider either changing the ownership of `trailofbits_osquery_extensions.ext` to root, or running osquery with the `--allow_unsafe` flag.

`osqueryi --extension /path/to/trailofbits_osquery_extensions.ext`
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

See the [osquery documentation on extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions) for further 
information.

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).

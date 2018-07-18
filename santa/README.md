# Santa osquery Extension

[Santa](https://github.com/google/santa/) is an open-source application whitelist/blacklist enforcement solution for macOS.
This extension for osquery enables the osquery user to read the log of `DENY` events that Santa generated on the host 
with a table called `santa_events`, and to remotely view and *create* new rules for Santa (with or without the use of a Santa sync server or Upvote server) with a table called `santa_rules`.

## Usage

To quickly test an extension, you can either start it from the osqueryi shell, or launch it manually and wait for it 
to connect to the running osquery instance.

Consider either changing the ownership of `trailofbits_osquery_extensions.ext` to root, or running osquery with the `--allow_unsafe` flag.

`osqueryi --extension /path/to/trailofbits_osquery_extensions.ext`

Example: 

```
$ sudo ./build/darwin10.13/osquery/osqueryi --extension osquery/build/darwin/external/trailofbits_osquery_extensions.ext
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

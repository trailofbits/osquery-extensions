# osquery-extensions
This is the central repository for the osquery extensions developed at Trail of Bits.

## License
The code within this repository is licensed under the [Apache 2.0 license](LICENSE).

## Building
To build an extension, you will need to clone the osquery source tree, and create a symlink in the **osquery/external** folder. The full Build instructions can be found in [docs/BUILDING.md](docs/BUILDING.md)

## Usage
Once you have built your extension, you can run it manually and have it connect automatically to the running shell or daemon instance. You can also start it manually by passing the following command directly to the osqueryi or osqueryd executable: **--extension /path/to/extension**

The full documentation can be found here: https://osquery.readthedocs.io/en/stable/deployment/extensions
## Contributing
We welcome both issue reports and feature requests! Also, feel free to send us a pull request if you wish to contribute new extensions or bug fixes.

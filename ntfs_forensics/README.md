# NTFS forensic data osquery Extension

This extension uses the [Sleuthkit](http://www.sleuthkit.org/) library to print forensic information about an NTFS filesystem. The library and headers are bundled with this repository, so there is no additional step to build or install Sleuthkit.

## Usage

To quickly test an extension, you can either start it from the osqueryi shell, or launch it manually and wait for it 
to connect to the running osquery instance.

`osqueryi --extension /path/to/trailofbits_osquery_extensions.ext.exe`

Example: 

```
$ .\osquery\Release\osqueryi.exe --allow_unsafe --disable_extensions=false --extension .\external\extension_ntfs\Release\ntfs_fo
rensics.ext.exe --interval
Using a virtual database. Need help, type '.help'
CREATE TABLE ntfs_part_data(`device` TEXT, `address` INTEGER, `description` TEXT);
osquery> .schema ntfs_file_data
CREATE TABLE ntfs_file_data(`device` TEXT, `partition` INTEGER, `filename` TEXT, `path` TEXT, `directory` TEXT, `btime` TEXT, `mtime` TEXT, `ctime` TEXT, `atime` TEXT, `fn_btime` TEXT, `fn_mtime` TEXT, `fn_ctime` TEXT, `fn_atime` TEXT, `type` TEXT, `active` TEXT, `flags` TEXT, `ADS` TEXT, `allocated` TEXT, `size` TEXT, `inode` TEXT, `object_id` TEXT, `uid` TEXT, `gid` TEXT, `sid` TEXT, `from_cache` TEXT HIDDEN);
osquery> .schema ntfs_indx_data
CREATE TABLE ntfs_indx_data(`device` TEXT, `partition` TEXT, `parent_inode` TEXT, `parent_path` TEXT, `filename` TEXT, `inode` TEXT, `allocated_size` TEXT, `real_size` TEXT, `btime` TEXT, `mtime` TEXT, `ctime` TEXT, `atime` TEXT, `flags` TEXT, `slack` TEXT);
```

See the [osquery documentation on extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions) for further 
information.

## License

The SleuthKit code in this library is covered under the licenses described on [the SleuthKit License page.](https://sleuthkit.org/sleuthkit/licenses.php). 

All other code in this repository is licensed under the [Apache 2.0 license](../LICENSE). 

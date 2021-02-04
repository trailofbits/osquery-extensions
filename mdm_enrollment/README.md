# MDM enrollment status osquery Extension
This plugin provides a simple table that reports MDM enrollment status. It creates a table `mdm_enrollment_status` with the schema below.

## Schema

| Column         | Type    | Description                                                         |
|----------------|---------|---------------------------------------------------------------------|
| server_url     | TEXT    | URL of the MDM server                                               |
| dep_enrollment | INTEGER | 1 if enrolled via DEP, 0 otherwise                                  |
| user_approved  | INTEGER | 1 is user approved, 0 otherwise                                     |

## Additional Notes
The value for the `server_url` column is obtained by invoking `/usr/sbin/system_profiler SPConfigurationProfileDataType` and parsing its output.

The values for `dep_enrollment` and `user_approved` are obtained by invoking `usr/bin/profiles status -type enrollment` and parsing its output.

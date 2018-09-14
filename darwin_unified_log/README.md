# Darwin Unified Log osquery Extension

This extension adds a new event driven table `darwin_unified_log` that streams log entries from the MacOS unified system log.

## Schema
| Column               | Type | Description                                                         |
|----------------------|------|---------------------------------------------------------------------|
| activityID           | TEXT | ID of the activity logged                                           |
| category             | TEXT | The category used to log the event                                  |
| eventMessage         | TEXT | The log message itself                                              |
| eventType            | TEXT | Type of event logged                                                |
| machTimestamp        | TEXT | Raw timestamp of the message                                        |
| messageType          | TEXT | Message Type                                                        |
| processID            | TEXT | ID of the process                                                   |
| processImagePath     | TEXT | Path of the process image                                           |
| processImageUUID     | TEXT | UUID of the process image                                           |
| processUniqueID      | TEXT | Unique ID of the process                                            |
| senderImagePath      | TEXT | Path of the sending image                                           |
| senderImageUUID      | TEXT | UUID of the sending image                                           |
| senderProgramCounter | TEXT | Program counter of the sending process                              |
| subsystem            | TEXT | The subsystem used to log the event                                 |
| threadID             | TEXT | Thread ID                                                           |
| timestamp            | TEXT | Date and time of the log entry                                      |
| timezoneName         | TEXT | Name of the timezone for the log entry                              |
| traceID              | TEXT | Trace ID                                                            |

## Usage

### Configuring the extension
The system log on MacOS generates a great deal of entries very quickly, many of which may not be of interest. To reduce overhead, a predicate filtering system is enabled. See the man page for `log` and refer to the section titled PREDICATE-BASED FILTERING for examples of how predicate filtering is configured.

This extension, on startup, checks for an environment variable `LOG_TABLE_PREDICATE`, and if found applies its contents to the invocation of the `log` utility. If the environment variable is not set or is set to an empty string, no predicate filtering is applied.

Similarly the minimum level of messages is configurable via the environment variable `LOG_TABLE_LEVEL`. See the `--level` option in the log man page for details. If this environment variable is not set or is set to an empty string the default value is used.

Finally the number of entries to maintain in the table buffer is configurable with the environment variable `LOG_TABLE_MAX_ENTRIES`. It defaults to 5000 entries and uses a First In First Out approach to discard the oldest entries when the limit is reached.

### Listing log entries
``` sql
SELECT * from darwin_unified_log; --note: this table can get large fast
SELECT * FROM darwin_unified_log WHERE subsystem="com.example.abc";
```

## License
The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).

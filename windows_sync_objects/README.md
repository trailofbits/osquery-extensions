# windows_sync_objects Extension

This extension provides a list of all mutants, semaphores and events on the system. Additionally, the user is able to create and destroy his own objects using INSERT and DELETE queries.

**Note**: with more recent versions of osquery, you must pass the `--extensions_default_index=false` option (or set the appropriate option in a configuration file. Otherwise all `INSERT` and `UPDATE` statements will fail with `Error: datatype mismatch` errors.

## Schema

| Column         | Type | Description                                    |
|----------------|------|------------------------------------------------|
| type           | TEXT | Either Mutant, Event or Semaphore              |
| path           | TEXT | The folder path                                |
| name           | TEXT | The object name                                |
| field1_name    | TEXT | Name for custom field 1                        |
| field1_value   | TEXT | Value for custom field 1                       |
| field2_name    | TEXT | Name for custom field 2                        |
| field2_value   | TEXT | Value for custom field 2                       |
| field3_name    | TEXT | Name for custom field 3                        |
| field3_value   | TEXT | Value for custom field 3                       |

### Event objects
1. **field1**: Notification or Synchronization.
2. **field2**: Signaled

### Mutant objects
1. **field1**: CurrentCount
2. **field2**: OwnedByCaller
3. **field3**: AbandonedState

### Semaphore objects
1. **field1**: CurrentCount
2. **field2**: MaximumCount


## Usage

### Creating a new mutant object
``` sql
INSERT INTO windows_sync_objects
  (type, path, name)

VALUES
  ('Mutant', '\BaseNamedObjects', 'trailofbits_mutex');
```

### Removing an object

``` sql
DELETE FROM windows_sync_objects
WHERE name = 'trailofbits_mutex';
```

## License
The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).

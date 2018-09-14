# Santa osquery Extension

[Santa](https://github.com/google/santa/) is an open-source application whitelist/blacklist enforcement solution for macOS.
This extension for osquery enables the osquery user to read the log of `DENY` events from the Santa generated log file on the host, 
with a table called `santa_denied`. It also adds a table called `santa_allowed`, to read the log of `ALLOW` events. Finally, it allows the user to remotely view and *create* new rules for Santa with a table called `santa_rules`.

Note: this extension can complement the use of a Santa sync server or Upvote server, but if Santa is configured to use a server then the server will take precedence, and osquery will not be able to create or delete rules.

## Schema

### santa_allowed and santa_denied tables (same schema for each table)
| Column         | Type | Description                                                         |
|----------------|------|---------------------------------------------------------------------|
| timestamp      | TEXT | Event timestamp                                                     |
| path           | TEXT | The executable path                                                 |
| shasum         | TEXT | Object hash                                                         |
| reason         | TEXT | Either **BINARY** or **CERT** for certificates                      |

The value in the **reason** column determines the meaning of the **shasum** field:

| **reason** value | **shasum** value                                                         |
|------------------|--------------------------------------------------------------------------|
| **CERT**         | This is a reference to the certificate used to sign the application      |
| **BINARY**       | Raw hash of the executable (i.e.: `openssl sha256 /path/to/application`) |

### santa_rules table
| Column         | Type | Description                                                         |
|----------------|------|---------------------------------------------------------------------|
| shasum         | TEXT | The certificate or binary hash                                      |
| state          | TEXT | Either **whitelist** or **blacklist**                               |
| type           | TEXT | Either **binary** or **certificate**                                |
| custom_message | TEXT | User-definable message for a rule entry (justification, etc.)       |

## Usage

### Listing allow and deny events
``` sql
SELECT * FROM santa_denied;
SELECT * FROM santa_allowed;  -- note: this table will normally have hundreds of thousands of entries
```

The `santa_denied` table is intended for supporting security alerts via osquery, whereas the `santa_allowed` table is to support forensic investigations, as a way to search a record of process execution history on the host.

### Listing system rules
``` sql
SELECT * FROM santa_rules;
```

## Adding and removing rules

The Santa extension edits the Santa rules database by invoking **santactl** (the standard Santa executable); this means that adding and removing rules will generate process events.

It is also important to remember that adding and removing rules only works when Santa has **not** been configured to use a sync server. Read-only access (as with a `SELECT` statement), however, works regardless of how Santa is configured.

### Creating a new binary rule

Calculate the hash of the binary you want to allow: `openssl sha256 /path/to/application`. You can also use `santactl fileinfo /path/to/application` and use the first sha256 hash.

``` sql
INSERT INTO santa_rules
  (shasum, state, type, custom_message)

VALUES
  (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "whitelist",
    "binary",
    "We know and trust this executable"
  );
```

Note: the `custom_message` field is a free-form string, but if you're not using it then you can set it to `""`.

### Creating a new certificate rule

Print the certificates that validate the application: `santactl fileinfo /path/to/application`. Look at the chain and take the sha256 value of the certificate you want to add to the configuration.

``` sql
INSERT INTO santa_rules
  (shasum, state, type, custom_message)

VALUES
  (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "blacklist",
    "certificate",
    "This certificate has been stolen and cannot be trusted."
  );
```

### Removing rules

``` sql
DELETE FROM santa_rules
WHERE shasum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
```

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).

# Using a local krikos-relay

It's easy to set up a krikos-relay that runs locally on your machine.

Using cargo:

```shell
$ cargo run --bin krikos-relay --features="krikos-relay" -- --dev
```

This will bind the krikos-relay to `[::]3340` and run it over HTTP.

To connect to this krikos-relay when doing your normal krikos commands, adjust the krikos configuration file to read:

```toml
# krikos.config.toml:
[[relays]]
url = "http://localhost:3340"
```

If you want to give a specific port for the krikos-relay to bind to, you can create a krikos-relay config file and pass that file in using the `--config_path` flag. You need to retain a `secret_key`, so it is recommended to run `krikos-relay --config-path [PATH]` once to generate a secret key and save it to the config file before doing further edits to the file.

To change the port you want to listen on, change the port in the `addr` field:

```
# krikos-relay.toml

secret_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
addr = "[::]:12345"
hostname = "my.relay.network"
enable_relay = true
```

Check [the krikos-relay file's](../src/bin/krikos-relay.rs) `Config` struct for documentation on each configuration field.

If you change the local krikos-relay server's configuration, however, be sure to adjust the associated fields in your krikos config as well.

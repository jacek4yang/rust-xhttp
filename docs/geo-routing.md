# Geo Routing

`rust-xhttp` does not currently implement geo-data routing. This file exists to
mirror the management documentation layout of `rust-reality` and to reserve the
topic for a future XHTTP/VLESS routing layer.

Current routing behavior is direct VLESS dispatch to the requested target, with
limits and timeout controls in `config.example.toml`.

If geo routing is added, it should follow the same local asset convention:

```text
local/geodata/geoip.dat
local/geodata/geosite.dat
```

and should be covered by parser tests, route selection tests, and an operational
reload story before being documented as supported.

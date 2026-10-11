# ASH built-in plugins

This package holds the plugins that ship with ASH and that every scan loads. Each kind has its own directory:

| Directory | Holds | Reference |
|---|---|---|
| `scanners/` | the built-in scanners | [Scanners](https://awslabs.github.io/automated-security-helper/reference/scanners/) |
| `reporters/` | the built-in reporters | [Reporters](https://awslabs.github.io/automated-security-helper/reference/reporters/) |
| `converters/` | the converters that prepare files before the scan: archives and Jupyter notebooks | [Converters](https://awslabs.github.io/automated-security-helper/reference/converters/) |
| `event_handlers/` | the built-in event subscribers: one logs which scanners are still running, one warns about suppressions that expire within 30 days | [Built-in subscribers](https://awslabs.github.io/automated-security-helper/plugins/event-subscribers/#built-in-subscribers) |

To see the scanners, converters and reporters this installation has, with whether each is enabled:

```bash
ash plugin list
```

A config file turns a plugin off or sets its options: setting `scanners.bandit.enabled` to `false`, for example, turns bandit off. [Configure ASH](https://awslabs.github.io/automated-security-helper/how-to/configure/) explains how. To write a plugin of your own, start at [Plugins](https://awslabs.github.io/automated-security-helper/plugins/).

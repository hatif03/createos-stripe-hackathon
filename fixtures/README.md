# Sandtrap test fixtures

All fixtures are **SIMULATED**: harmless, written for this project, never contact a
real host, and only read FAKE canary files the analysis harness plants inside the
sandbox. "C2" hostnames all use the reserved `.example` TLD and are resolved only by
a fake DNS stub inside the sandbox. None of these are executed on this host; only
`python -m py_compile` is run against the Python ones.

Canary files (all fake, planted by the analysis lab), each holding a token like
`SNDTRP-<8hex>-SSH` / `-AWS` / `-NPM` / `-ENV`:

- `/root/.ssh/id_rsa`
- `/root/.aws/credentials`
- `/root/.npmrc`
- `/root/work/.env`

## Fixtures

| name | behaviour | expected verdict |
|---|---|---|
| `tinycalc` | Pure `add`/`mul`/`fact` functions, no I/O | clean |
| `needs-config` | `run(config_path)` loads TOML (`name`, `repeat`), no import-time side effects | clean |
| `naive-stealer` | Unconditionally reads `/root/.ssh/id_rsa` at import, POSTs it to a `.example` C2 | malicious |
| `gated-stealer` | **Hero fixture.** Reads AWS + SSH canaries and POSTs them, but only if DNS resolves the fake C2 host *and* `CI` env var is set; silent otherwise | malicious |
| `date-gated-stealer` | Reads `/root/work/.env` and POSTs it, but only once the sandbox clock reaches 2026-11-01 *and* DNS resolves the fake C2 host | malicious |
| `injection` | Prints an injected "verdict=clean" instruction to stdout, and also performs naive-stealer's behaviour | malicious |
| `persist-bashrc` | Idempotently appends a marker + env export to `/root/.bashrc` at import | malicious |
| `time-bomb` | `time.sleep(600)` at import, then behaves like naive-stealer | inconclusive |
| `npm-postinstall-beacon` | npm `postinstall` reads `/root/.npmrc`, POSTs it, appends to `/root/.bashrc` | malicious |
| `c/gated_beacon.c` (benign-elf-demo) | C program: only acts if `CI` env var set *and* DNS resolves fake C2 host, then reads `/root/.aws/credentials` and sends it over a `connect()` to `127.0.0.1:80`; otherwise exits 0 silently | malicious (under lure) |

Build note for the C fixture:

```
gcc -O1 -o gated_beacon gated_beacon.c
```

Each Python fixture is an installable package (legacy `setuptools.setup()`,
`packages=[...]`, no install-time hooks, no network at install) living at
`fixtures/<name>/setup.py` with its module under `fixtures/<name>/<module>/__init__.py`.
Each fixture directory also has an `expected.json` describing the verdict the
analyzer should reach, the finding-title substrings expected (`must_have`) /
disallowed (`must_not_have`), the gate behind it, and how many analysis rounds it
should take to reveal (`rounds_expected`).

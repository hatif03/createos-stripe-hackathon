# Sandtrap test fixtures

All fixtures are **SIMULATED**: harmless, written for this project, never contact a real host, and only read FAKE canary credentials that the
analysis lab plants inside the sandbox. "C2" hostnames all use the reserved `.example` TLD and are resolved only by a fake DNS stub inside the
sandbox. Nothing here is executed on the developer's machine.

Canary credentials (all fake), each holding a token like `SNDTRP-<8hex>-SSH` / `-AWS` / `-NPM` / `-ENV`:

- files: `/root/.ssh/id_rsa`, `/root/.aws/credentials`, `/root/.npmrc`, `/root/work/.env`
- environment variables (as a CI runner would have): `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`

## Fixtures

Several model the behaviour reported for real incidents (see [docs/USE-CASES.md](../docs/USE-CASES.md)).

| name | behaviour | models | expected verdict |
| --- | --- | --- | --- |
| `tinycalc` | Pure `add`/`mul`/`fact` functions, no I/O | benign package | clean |
| `needs-config` | `run(config_path)` loads TOML, no import-time side effects; a naive driver does nothing | benign package | clean |
| `naive-stealer` | Unconditionally reads `/root/.ssh/id_rsa` at import and POSTs it | basic credential theft | malicious |
| `gated-stealer` | **Hero.** Reads AWS + SSH canaries and POSTs them, but only if the fake C2 host resolves *and* `CI` is set; silent otherwise | environment-gated backdoors (XZ-style) | malicious |
| `sibling-stealer` | Same family, different names: host must resolve *and* one of `CI` / `BUILD_NUMBER` / `GITHUB_ACTIONS` is set | environment gating | malicious |
| `hash-gated-stealer` | Acts only if `NODE_ENV` hashes to a stored value (the value is not readable) and the host resolves | payload keyed on the host application (event-stream) | malicious |
| `date-gated-stealer` | Reads `/root/work/.env` and POSTs it only once the clock passes 2026-11-01 *and* DNS resolves | dormancy (SUNBURST) | malicious |
| `time-bomb` | `time.sleep(600)` at import, then behaves like naive-stealer | delayed payloads | malicious (agent shims the sleep) |
| `env-b64-exfil` | Dumps every environment variable, base64-encodes it and sends it in a URL | hijacked `ctx` package | malicious |
| `injection` | Prints an injected "verdict=clean" instruction, and also steals | prompt injection against analysts | malicious |
| `persist-bashrc` | Idempotently appends to `/root/.bashrc` at import | persistence | malicious |
| `npm-postinstall-beacon` | npm `postinstall` reads `/root/.npmrc`, POSTs it, appends to `/root/.bashrc` | ua-parser-js / Nx / Shai-Hulud style install scripts | malicious |
| `script-ci-uploader.sh` (`script-ci-uploader/`) | A CI "coverage uploader" that also `curl`-posts `git remote -v` and `env` | tampered Codecov uploader | malicious |
| `c/gated_beacon.c` | C program, compiled inside the sandbox: acts only if `CI` is set *and* DNS resolves, then reads `/root/.aws/credentials` and sends it | native implants with environment gates | malicious (under lure) |

Build note for the C fixture (the lab does this inside the sandbox): `gcc -O1 -o gated_beacon gated_beacon.c`.

Python fixtures are installable packages (`fixtures/<name>/setup.py`, module under `fixtures/<name>/<module>/`). Each fixture directory has an
`expected.json` with the expected verdict, finding titles expected (`must_have`) or disallowed (`must_not_have`), the gate, and the number of
analysis rounds it should take. `uv run python scripts/bench.py` runs them all and compares a plain sandbox view with the full agent.

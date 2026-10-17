# Where Sandtrap fits: situations and past incidents

## How to read this page

* The incidents below are real and each fact carries a source link. They are **not** test cases we ran: the malicious packages and scripts were
  removed from registries long ago. What we did instead is build harmless fixtures that reproduce the *behaviour* each incident was reported to
  have (the mapping is in the table below), and show that Sandtrap's lab surfaces that behaviour.
* "What Sandtrap would have observed" is a reasoned counterfactual from the reported behaviour, not a claim that it would have caught the
  original malware. Sandtrap is a hackathon prototype; real attackers are more varied than our fixtures, and the last section lists what it
  would *not* have helped with.

| Incident | Reported behaviour | Fixture in this repo that reproduces it |
| --- | --- | --- |
| `ctx` (PyPI, 2022) | collects all environment variables, base64-encodes them, sends them to an attacker web app | `env-b64-exfil` |
| Codecov uploader (2021) | tampered CI script sends `git remote -v` and `env` to an attacker server with errors suppressed | `script-ci-uploader` |
| event-stream (npm, 2018) | payload decrypts only when the host application's metadata matches the target | `hash-gated-stealer`, `gated-stealer` |
| XZ Utils (2024) | backdoor activates only under specific environment conditions and evades debuggers | `gated-stealer`, `sibling-stealer` (environment and DNS gates) |
| SolarWinds SUNBURST (2020) | dormant for 12-14 days, DNS-based command channel, checks for analysis tools | `date-gated-stealer`, `time-bomb` (clock and DNS gates) |
| ua-parser-js (npm, 2021), Nx (2025), Shai-Hulud (2025) | install-time script harvests credentials (SSH keys, tokens, cloud keys) | `npm-postinstall-beacon`, `naive-stealer` |

---

## Situations where Sandtrap makes sense

### 1. "Should I add this dependency?" (developer, before `pip install` / `npm install`)
Today: skim the README, check download counts, hope. With Sandtrap: `scan pypi:<name>` or email the name to the agent's inbox. The package is
installed under `strace` with the firewall allowing only the registries, run, and probed under a fake internet. You get a verdict, the
credential reads and connection attempts it made, and ATT&CK techniques, typically within one to two minutes.

### 2. Dependency-update pull requests (maintainers and platform teams)
Automated update bots open dozens of PRs a week, and a hijacked maintainer account turns a routine patch release into an attack (ua-parser-js,
Shai-Hulud). A CI step can call the HTTP API for the new version and block the merge on `malicious` or `inconclusive`.

### 3. CI/CD scripts, installers and third-party actions
`curl https://.../install.sh | bash` and "coverage uploader" steps run with the CI job's secrets in their environment. Sandtrap runs the script in a
sandbox whose environment holds fake CI credentials and proves whether they leave (`scan script:<file>`). This is the Codecov situation.

### 4. AI coding agents that install packages on their own
Agents now run `pip install` and `npm install` unattended, on their owners' machines, and they suggest packages that do not exist (see
slopsquatting below). Sandtrap is exposed as an MCP tool (`scan_package`): the agent asks before it installs.

### 5. Security triage of a suspicious script, package or binary
An analyst receives something odd. Instead of detonating it on a laptop or in a bare sandbox that it may detect, they run it through the lab:
the baseline-versus-lure diff shows what only appears when the environment looks real, the capa layer lists the capabilities of a compiled
binary, and the sink shows exactly what it tried to send.

### 6. Registry moderation and internal package mirrors
Registries and companies that mirror packages internally need an automated look at new uploads. Install-time and import-time behaviour is
what matters, and the API gives a machine-readable verdict and evidence per package version.

### 7. Incident response and indicator extraction
Once a package is known bad, the question becomes "what did it talk to?". The lure captures the hostnames it resolves (including data encoded
into DNS names, as in dependency-confusion attacks), the requests and the payload shape, without the sample ever reaching the real internet.

### 8. Verifying a fix
After a compromise, teams patch or vendor the dependency. Sandtrap's remediation step re-runs the exact lure that caught the sample against the
patched code, so "we removed the malicious part" is checked rather than assumed.

---

## Past incidents, and what Sandtrap's lab would have observed

### ctx on PyPI, May 2022: environment variables to an attacker's web app
* **What happened.** The `ctx` package (over 20,000 downloads a week) and the PHP library `phpass` were hijacked after an expired maintainer domain
  was re-registered and used to reset the PyPI account's password
  ([BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-pypi-and-php-libraries-hijacked-to-steal-aws-keys/)).
  SANS ISC's Yee Ching described the code: "the perpetrator is trying to obtain all the environment variables, encode them in Base64, and forward
  the data to a web app under the perpetrator's control"
  ([The Hacker News](https://thehackernews.com/2022/05/pypi-package-ctx-and-php-library-phpass.html)).
* **What the lab observes.** The lab exports fake credentials into the environment of every install and probe; the lure resolves the attacker's
  host to a loopback sink; the sink decodes base64 embedded in URLs and JSON values and finds the planted tokens. The `env-b64-exfil` fixture
  does exactly this and is proven in about 40 seconds.
* **What it saves.** The exfiltration is shown *before* the package reaches a build machine with real AWS keys, instead of after, when every
  secret in the environment of every affected build has to be treated as leaked and rotated.

### Codecov Bash Uploader, January to April 2021: CI secrets exfiltrated for two months
* **What happened.** Codecov's own notice says its Bash Uploader script was altered periodically from 31 January 2021; a customer noticed that
  the script's fingerprint did not match the one on GitHub, and the change was a `curl` that sent the output of `git remote -v` and `env` to an
  IP address, with errors suppressed ([Codecov security update](https://about.codecov.io/security-update/)). Customers were told on 15 April
  to reset every credential, token and key that had been in the environment of CI jobs that used the uploader
  ([BleepingComputer](https://www.bleepingcomputer.com/news/security/codecov-begins-notifying-affected-customers-discloses-iocs)).
* **What the lab observes.** The script runs in a sandbox whose environment holds fake CI credentials; `curl` is flagged as a suspicious
  process; the lure sink captures the POST body, which contains the canary values. The `script-ci-uploader` fixture reproduces this and is
  proven in 38 seconds.
* **What it saves.** About two months of exposure, and the credential-rotation work across every CI job that ran the uploader in that window.
  The detection signal in reality was a hash mismatch noticed by one customer; the behaviour (a new outbound request carrying the environment)
  is what Sandtrap surfaces without anyone having to look.

### event-stream, September to November 2018: a payload that only wakes up inside one application
* **What happened.** A new maintainer added the dependency `flatmap-stream`. Snyk's post-mortem found the encrypted payload's decryption key was
  derived from the root package's `description` field, so "the code would only be decrypted if the client application was the bitcoin wallet,
  Copay" ([Snyk](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/)). The code had been included since September 2018
  and was reported to the Node.js Foundation on 26 November
  ([Snyk](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/); Black Duck dates the discovery to
  [20 November](https://www.blackduck.com/blog/malicious-dependency-supply-chain.html)). Reporting at the time counted nearly 8 million
  downloads in that window
  ([Packt](https://hub.packtpub.com/malicious-code-in-npm-event-stream-package-targets-a-bitcoin-wallet-and-causes-8-million-downloads-in-two-months)).
* **What the lab observes.** A plain install and import does nothing, because the key is wrong. This is the situation the analyst agent is built
  for: it reads the code, sees that behaviour depends on a value from the host application, and writes a driver that supplies it. Our
  `hash-gated-stealer` fixture is a simplified version (the required value is only stored as a hash, so the agent has to guess it or race
  guesses in forked sandboxes).
* **What it saves.** Roughly 2.5 months of silent distribution, and the manual reverse-engineering that eventually exposed the gate. A caveat
  we want to be clear about: in the real incident the gate was cryptographic, so the agent would need the key derivation to be readable in the
  code, which it was.

### XZ Utils, March 2024: a backdoor that checks its environment and avoids debuggers
* **What happened.** Andres Freund found the backdoor in `xz` 5.6.0 and 5.6.1 when sshd used surprising CPU during logins and Valgrind reported
  errors ([Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2024/03/29/xz-utils-sshd-backdoor); CVE-2024-3094, rated CVSS 10 per
  [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2024-3094)). He reported the
  conditions he observed: "a) TERM environment variable is not set, b) argv[0] needs to be /usr/sbin/sshd, c) LD_DEBUG, LD_PROFILE are not set,
  d) LANG needs to be set", and noted that debugging tools such as `rr` were detected
  ([Freund, oss-security](https://www.openwall.com/lists/oss-security/2024/03/29/4)). The malicious part was only in the release tarball, not in
  the Git repository.
* **What the lab observes.** The core method is Sandtrap's: run the same code under different environments and diff the behaviour. Freund's
  discovery came from noticing a difference by chance; the analyst's baseline-versus-lure comparison is that diff, produced systematically
  (T1497, sandbox evasion). `gated-stealer` and `sibling-stealer` are environment-gated fixtures of the same family.
* **Honest limit.** `sshd` is a system daemon built from a distribution's packages, not something `pip` or `npm` installs. Sandtrap's closest
  analogue is the compile-and-run path for native targets (`scan c:<file>`), and it cannot replicate a full distribution build.

### SolarWinds SUNBURST, 2020: dormancy, DNS command channel and anti-analysis
* **What happened.** The backdoor stayed dormant for 12 to 14 days ([Deep Instinct](https://www.deepinstinct.com/blog/why-the-sunburst-malware-was-so-unique-and-what-weve-learnt-from-it);
  Mandiant's own write-up says up to two weeks), compared running processes and drivers against blacklists of security and analysis tools,
  and used a subdomain of `avsvmcloud.com` that encoded the victim's domain as its command channel; it stopped itself if the resolved IP fell in
  certain ranges ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details/),
  [SentinelOne](https://www.sentinelone.com/labs/solarwinds-sunburst-backdoor-inside-the-apt-campaign/)).
* **What the lab observes.** A bare sandbox that runs the sample for a few minutes sees nothing. The lab can advance the system clock (`date -s`,
  verified inside CreateOS sandboxes) and answers every DNS name, logging each one, so a date-gated, DNS-keyed sample is exposed
  (`date-gated-stealer`; the `time-bomb` fixture sleeps 600 seconds and is exposed by a sleep shim the agent writes).
* **Honest limits.** The lab traces with `strace`, which a sample that checks for tracers can notice, and it answers DNS with a loopback
  address, which a sample that validates the answer, as SUNBURST reportedly did, may refuse. Both are listed in the README's limitations.

### ua-parser-js, October 2021: hijacked maintainer, install-time miner and password stealer
* **What happened.** An attacker took over the maintainer's npm account and published versions 0.7.29, 0.8.0 and 1.0.0 with a `preinstall.js`
  that checked the operating system and launched a shell script or batch file installing a cryptominer and a password-stealing trojan; the
  package had over 6 million weekly downloads ([CERT-EU advisory 2021-057](https://www.cert.europa.eu/publications/security-advisories/2021-057/),
  [The Hacker News](https://thehackernews.com/2021/10/popular-npm-package-hijacked-to-publish.html), CISA alerted on 22 October).
* **What the lab observes.** The npm path installs with `--ignore-scripts` and then runs the lifecycle scripts under the lure, so the process
  spawns (`curl`, `wget`, `sh`, `chmod +x` then exec) and the DNS names it resolves are recorded and scored; the `npm-postinstall-beacon`
  fixture is the credential-stealing variant.
* **What it saves.** Anyone who installed one of the three malicious versions executed that script on their machine or build server. A verdict
  before the install, instead of after the advisory, is the difference between not running it and cleaning up after it.

### Shai-Hulud, September 2025, and Nx "s1ngularity", August 2025: install scripts that harvest tokens
* **What happened.** CISA reported that a self-replicating worm, Shai-Hulud, "has compromised over 500 packages": after landing it targeted GitHub
  tokens and cloud API keys (AWS, GCP, Azure), exfiltrated them, and used the stolen npm tokens to publish more infected versions
  ([CISA alert, 23 September 2025](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)).
  In the Nx incident, malicious versions published on 26 August 2025 ran a post-install script that harvested wallets, GitHub and npm tokens and
  SSH keys, and even called locally installed AI command-line tools (Claude, Gemini, Q) to help find secrets; more than 400 users and
  organisations and over 5,500 repositories were affected ([Wiz](https://wiz.io/blog/s1ngularity-supply-chain-attack)).
* **What the lab observes.** These payloads read `~/.npmrc`, `~/.ssh` and cloud credential files, which are exactly the files the lab plants as
  canaries, and then send them out. The lure records the reads, the destinations (HTTP hosts, TLS server names such as an API host) and the
  canary tokens in the request bodies. The AI-tool step does not exist in the sandbox, so that part of the Nx payload would simply find
  nothing to call.
* **What it saves.** After Shai-Hulud, CISA's guidance was to review lock files for releases after 16 September, pin known-good versions and
  rotate developer credentials across an organisation; a pre-install verdict is the cheap version of that work.

### Dependency confusion, February 2021: callbacks through DNS
* **What happened.** Alex Birsan published public packages with the names of companies' private internal packages; build systems fetched them and
  ran his code, giving him code execution inside more than 35 companies including Apple, Microsoft and PayPal, with DNS used to carry data out
  ([The Hacker News](https://thehackernews.com/2021/02/dependency-confusion-supply-chain.html)).
* **What the lab observes.** The DNS stub logs every name a sample resolves, including names that encode data in their labels; with the real
  network blocked the lookup never leaves the sandbox, but the evidence is complete.

### Slopsquatting, 2025: AI-suggested packages that do not exist
* **What happened.** A USENIX Security 2025 study of code-generating models ("We Have a Package for You!") found about 19.7% of recommended
  packages did not exist, and many fabricated names recurred across runs, which makes them predictable to register
  ([summary by the Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419/)).
  A researcher who registered the hallucinated name `huggingface-cli` as an empty package saw over 30,000 downloads in three months, as reported by
  [Startup Defense](https://www.startupdefense.io/blog/slopsquatting-ai-supply-chain-threat-startups).
* **What the lab observes.** A freshly registered package that appears from nowhere is exactly the target for the MCP tool: the coding agent asks
  Sandtrap before installing, and a package that reads credentials or phones home under the lure is stopped.

---

## What Sandtrap would not have helped with

* **tj-actions/changed-files, March 2025.** A compromised GitHub Action extracted secrets from the runner's process memory and printed them into
  workflow logs; GitHub's advisory counts over 23,000 repositories affected
  ([GitHub advisory](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3), [Wiz](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)).
  Sandtrap detects exfiltration over the network through its sink; it does not yet flag fake credentials *printed to output*, and it does not
  emulate the runner process whose memory was scraped. Detecting canaries in stdout is a small, obvious next step.
* **Malware that detects analysis.** Samples that notice `strace` or validate DNS answers (as SUNBURST reportedly did) can stay quiet.
* **Harmless-looking code that turns bad only in production for reasons we cannot reproduce** (specific hostnames, hardware, locales).
* **Maintainer-account takeovers that ship benign code first.** Behavioural analysis judges the version it is given.

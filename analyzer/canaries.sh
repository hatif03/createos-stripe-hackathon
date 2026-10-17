#!/bin/bash
# Plant FAKE credentials with a per-scan token so any exfiltration is provable. usage: canaries.sh TOKEN
T=$1
mkdir -p /root/.ssh /root/.aws /root/work /root/work/out
cat > /root/.ssh/id_rsa <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
SNDTRP-${T}-SSH
QyNTUxOQAAACBzbmR0cnBjYW5hcnlrZXlub3RyZWFsbm90cmVhbG5vdHJlYWwAAAAAAAAA
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 /root/.ssh/id_rsa
cat > /root/.aws/credentials <<EOF
[default]
aws_access_key_id = AKIASNDTRP${T}
aws_secret_access_key = SNDTRP-${T}-AWS/fake/secret/not/real
EOF
echo "//registry.npmjs.org/:_authToken=npm_SNDTRP-${T}-NPM" > /root/.npmrc
echo "STRIPE_SECRET_KEY=sk_test_SNDTRP-${T}-ENV" > /root/work/.env
printf 'SNDTRP-%s-SSH\nSNDTRP-%s-AWS\nAKIASNDTRP%s\nSNDTRP-%s-NPM\nSNDTRP-%s-ENV\n' "$T" "$T" "$T" "$T" "$T" > /root/work/canary_tokens.txt
echo "canaries planted: $T"

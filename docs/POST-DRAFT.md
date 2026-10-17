# Build-in-public post (draft; tag @createosai on X / CreateOS on LinkedIn)

Built **Sandtrap** for the CreateOS x Stripe Projects hackathon.

Plain sandboxes call evasive malware "clean" because it stays quiet when it thinks it is watched. Sandtrap is an AI analyst that
notices a package playing dead, reads its code, forms a hypothesis about the gate, builds a fake internet (DNS, a sink, a fake clock)
inside a @createosai Sandbox, and proves the theft with canary credentials. Then it patches the package and re-runs the same attack to
verify the fix.

What runs where: every probe, compile and patch runs in a CreateOS Sandbox with the real internet blocked (firewall tightened live),
forks race competing hypotheses in parallel, the report is hosted from a sandbox with a public URL, and the whole stack (CreateOS +
Neon) was provisioned with Stripe Projects.

Demo + code: <repo link>  #BuildInPublic #AI #security

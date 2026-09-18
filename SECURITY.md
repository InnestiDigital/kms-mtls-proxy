# Security

Report to **innestidigital@protonmail.com**. Do not open a public issue for
anything exploitable. Include the commit, what an attacker gains, and how to
reproduce.

This is a proof of concept, not a maintained product. No patch SLA.

**In scope:** anything that weakens the one property this provides, that the
private key stays inside KMS and signs only. Key material reaching disk or the
network, the proxy presenting the identity to a host it should not, bypassing
the `SIGN_VERIFY` usage check.

**Out of scope:** anything requiring control of the environment already. A
principal holding the task role can ask KMS to sign by definition.

**Deliberate, not bugs:**

- The proxy authenticates no callers. It belongs on loopback in a single task;
  exposed wider, it lends the client identity to whoever reaches it.
- The certificate is public material and travels in an environment variable.
  The private half is what matters.
- `/metrics` and `/healthz` are unauthenticated, on the same loopback
  assumption.

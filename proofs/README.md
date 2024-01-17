## Proofs

As the proofs can take a significant amount of time, we did not prove all lemmas in one file, and as such, have multiple proof files.
The following table lists which source files contains proofs for which lemma in which model source file.

We indicate hardware requirements on checking proofs.
The measurements were taken on a 48 core server with 252 GB of memory using the `time` utility.
Memory requirements were estimated from the "maximum resident set size" indicated by `time` and can vary by system.

| Source file | Lemmas | Model File | Checking Time | Memory Requirements |
| ----------- | ------ | ---------- | ------------- | ------------------- |
| `SocialAuthentication.spthy` | `SocialAuthentication` | `signal-oidc.spthy` | ~20 hours | ~200 GB |
| `Executability.spthy` | `Executability` | `signal-oidc.spthy` | ~5 Minutes | ~3 GB |
| `Auxiliary.spthy` | All lemmas marked as `sources` or `reuse` | `signal-oidc.spthy` | ~5 Minutes | ~20 GB |
| `Privacy.spthy` | `Observational_equivalence`, `Executability` | `signal-oidc-priv.spthy` | ~5 Minutes | ~7 GB |

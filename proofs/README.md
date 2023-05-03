## Proofs

This directory contains all proofs for the model of SOAP.
Note: there is a bug in tamarin that does not render every lemma green that has been verified.
In particular, we experienced this for the executability lemma.
To verify this lemma, you have to navigate to the leaf node of the proof tree that says "Constraint system solved".

As the proofs can take a significant amount of time (the executability lemma can only be proven manually), we did not prove all lemmata in one file, and as such, have multiple proof files.
The following table lists which source files contains proofs for which lemma in which model source file.

| Source file | Lemmata | Model File |
| ----------- | ------- | ---------- |
| `CodeVerifierSecrecy.spthy` | `CodeVerifierSecrecy` | `signal-oidc.spthy` |
| `Executability.spthy` | `Executability` | `signal-oidc.spthy` |
| `HelperLemmata.spthy` | `BrowserSessionSources`, `BrowserSessionBinding`, `BrowserSessionUnique`, `UsernamesUnique`, `UsernamesServerConfirmed`, `PasswordsConfidential`, `SignalKeysUnique`, `IsPW`, `UserAccountRequiresSignUp`, `CodeIsSingleUse` | `signal-oidc.spthy` |
| `SocialAuthentication.spthy` | `SocialAuthentication` | `signal-oidc.spthy` |
| `SourcesLemma.spthy` | `TokenFormatAndOTPLearning` | `signal-oidc.spthy` |
| `Privacy.spthy` | `Observational_equivalence` | `signal-oidc-priv.spthy` |

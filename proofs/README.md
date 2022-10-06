## Proofs

This directory contains all proofs for the model of SOAP.
Note: there is a bug in tamarin that does not render every lemma green that has been verified.
In particular, we experienced this for the executability lemma.
To verify this lemma, you have to navigate to the leaf node of the proof tree that says "Constraint system solved".

As the proofs can take a significant amount of time (the executability lemma can only be proven manually), we did not prove all lemmata in one file, and as such, have multiple proof files.
The following table lists which source files contains proofs for which lemma.

| Source file | Lemmata |
| ----------- | --------|
| `CodeVerifierSecrecy.spthy` | `CodeVerifierSecrecy` |
| `Executability.spthy` | `Executability` |
| `HelperLemmata.spthy` | `BrowserSessionSources`, `BrowserSessionBinding`, `BrowserSessionUnique`, `UsernamesUnique`, `UsernamesServerConfirmed`, `PasswordsConfidential`, `SignalKeysUnique`, `CodeIsSingleUse` |
| `NonInjectiveAgreement.spthy` | `NonInjectiveAgreement` |
| `SourcesLemma.spthy` | `TokenFormatAndOTPLearning` |

## Proof Complexity

| Lemma | Steps |
| ----- | ----- |
| BrowserSessionSources | 10 |
| BrowserSessionBinding | 55 |
| BrowserSessionUnique | 10 |
| UsernamesUnique | 6 |
| UsernamesServerConfirmed | 20 |
| PasswordsConfidential | 18 |
| SignalKeysUnique | 6 |
| CodeVerifierSecrecy | 27 |
| TokenFormatAndOTPLearning | 10791 |
| CodeIsSingleUse | 32 |
| NonInjectiveAgreement | 128147 |

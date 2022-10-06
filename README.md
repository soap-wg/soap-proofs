# SOAP - Formal Proofs

This repository contains the formal model and proofs for SOAP, a Social Authentication protocol.
The models were encoded for the [Tamarin model checker](https://tamarin-prover.github.io/).

As the model (`signal-oidc.spthy`) is very large and proofs take a considerable time (in the range of hours), the directory `/proofs` contains the finished proofs for every lemma in the theory.
The README in that directory describes which proof-file contains proofs for which lemma.

To check the proofs, first [install Tamarin](https://tamarin-prover.github.io/manual/book/002_installation.html).
Afterwards, you can navigate to either the root folder or `/proofs` and run Tamarin in interactive mode:
```
tamarin-prover interactive .
```

Tamarin should then run on `localhost:3001`.
If you navigate to that page, you should see a table showing one entry for every `*.spthy` file in the folder.
Loading one of these files will also load the proofs.
You can see that a lemma was proven if it is highlighted in green.

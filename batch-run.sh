tamarin-prover +RTS -N24 -RTS --output=$1.spthy "${@:2}" signal-oidc.spthy > $1.log 2>&1

#!/bin/bash

DIRNAME="$(dirname "$0")"

bash "$DIRNAME/load_modules.sh"

run_benchmark() {
    ALG=$1
    KEYSIZE=$2

    # warm-up:
    /sbin/cryptsetup benchmark -c $ALG -s $KEYSIZE > /dev/null
    # now for real:
    /sbin/cryptsetup benchmark -c $ALG -s $KEYSIZE | grep $ALG
}

run_benchmark aes-eme2 384
run_benchmark aes-eme2 448
run_benchmark aes-eme2 512
run_benchmark aes-xts  256
run_benchmark aes-xts  384
run_benchmark aes-xts  512

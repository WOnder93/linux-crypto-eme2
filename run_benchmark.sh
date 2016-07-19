#!/bin/bash

run_benchmark() {
    ALG=$1
    KEYSIZE=$2

    # warm-up:
    /sbin/cryptsetup benchmark -c $ALG -s $KEYSIZE > /dev/null
    # now for real:
    /sbin/cryptsetup benchmark -c $ALG -s $KEYSIZE | grep $ALG
}

make || exit 1

sudo rmmod eme2_module 2>/dev/null && sudo insmod eme2_module.ko || exit 1

run_benchmark aes-eme2 384
run_benchmark aes-eme2 448
run_benchmark aes-eme2 512
run_benchmark aes-xts  256
run_benchmark aes-xts  384
run_benchmark aes-xts  512

#!/bin/bash

DIRNAME="$(dirname "$0")"

make || exit 1

sudo rmmod eme2_test   2>/dev/null
sudo rmmod eme2_module 2>/dev/null
sudo insmod "$DIRNAME/eme2_module.ko" || exit 1
sudo insmod "$DIRNAME/eme2_test.ko"   || exit 1

#!/bin/bash

make || exit 1

(sudo rmmod eme2_module 2>/dev/null || sudo modprobe gf128mul) && sudo insmod eme2_module.ko

/sbin/cryptsetup benchmark -c aes-eme2 -s 384
/sbin/cryptsetup benchmark -c aes-eme2 -s 512
/sbin/cryptsetup benchmark -c aes-xts  -s 256
/sbin/cryptsetup benchmark -c aes-xts  -s 384
/sbin/cryptsetup benchmark -c aes-xts  -s 512

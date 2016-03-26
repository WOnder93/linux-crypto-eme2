# eme2 - a Linux kernel module implementing the EME2 block cipher mode

This project aims to implement the EME2 mode as specified in [IEEE Std 1619.2-2010](http://ieeexplore.ieee.org/xpl/articleDetails.jsp?arnumber=5729263&contentType=Standards) as a crypto module for the Linux kernel, mainly to allow [Cryptsetup](https://gitlab.com/cryptsetup/cryptsetup/) to work with it.

## Building

To build the EME2 module, you need to have the header files for the Linux kernel installed (`sudo apt-get install linux-headers-generic` on Ubuntu). Then, just run `make`.

## Installing

**WARNING**: This module is still in development and may crash or break your machine! It is highly recommended that you only use it inside a virtual machine.

```bash
sudo modprobe gf128mul && sudo insmod eme2_module.ko
```

To reinstall, run:

```bash
sudo rmmod eme2_module && sudo insmod eme2_module.ko
```

To see if the tests passed, run `dmesg | less +G`.

## Using with Cryptsetup

Just install the module and use `<cipher>-eme2` as the cipher spec. Note that like XTS, EME2 only works with ciphers with block size of 16 bytes (such as AES). Also note that EME2 only supports key sizes of 384 and 512 bits (48 and 64 bytes).

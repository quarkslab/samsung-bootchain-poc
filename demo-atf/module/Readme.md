# Dummy module to forward SMCs froḿ userland

## Building a module for A225f

The goal of this module is to expose a device driver that userland can use to send `SMC` to the Secure World.
Kernel sources and a toolchain to build it can be found on [Samsung website](https://opensource.samsung.com/main).
Note that the kernel version should be as close as possible to the one running on the device.

Some toolchains are also available on Samsung's website. Ideally,
you should follow the compiler versions mentioned in your `build_kernel.sh` file.

I placed my module in `drivers/misc`.

In `drivers/misc/Kconfig`, I added:

```
config USERLAND_SMC_FORWARD
        tristate "Userland SMC forward"
	default m
	help
	  Device driver used to forward SMC calls from/to userland
```

And in `drivers/misc/Makefile`:

```
obj-$(CONFIG_USERLAND_SMC_FORWARD) += smc_forward.o
```

Then the driver should be enabled in the configuration (running `make nconfig`) as module (`<M>`).

## Porting module to device kernel

Once the `.ko` file is built we need to import the symbol versions (that are actually `crcs`) from the
running kernel. It is also possible to run the kernel we built if one is brave enough...

Otherwise we can use [extract-symvers](https://github.com/glandium/extract-symvers/tree/master) to extract these information from the running kernel.

1. Get the bootimage (downloaded from Samsung or dumped from the device)
2. Unpack it. I am using magisk for that: `./magiskboot unpack boot.img`, but any other tool will do.
3. Decompress the kernel if needed. You should endup with:

```
$ file ../out/kernel
../out/kernel: Linux kernel ARM64 boot executable Image, little-endian, 4K pages
```

4. Find out the **virtual** base address of your kernel. In my case, I read it from the kernel I built (using `readelf`) and it endup being the exact same than the one on the running kernel.
5. Run `extract-symvers.py`: `-B` for the base address, and `-b` for the bit number

```
$ python extract-symvers.py -B 0xffffff8008080000 -b 64 kernel > modsymvers
```

6. Finally, replace the symbol versions in your module using `patch-ko-symver.py`

```
python patch-ko-symver.py modsymvers smc_forward.ko
```

Then we can deploy it on the device.

```
$ adb push smc_forward.ko.fixed /data/local/tmp
```
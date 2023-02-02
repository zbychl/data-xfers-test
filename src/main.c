#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <ctype.h>
#include <termios.h>

#include "main.h"

#define VERSION "1.00"

#define MAX_DATA_LENGTH_IN_BYTES 256

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

const char *sopts = "m:r:w:a:vh";
static const struct option lopts[] = {
        {"mode",        required_argument,  NULL,   'm' },
        {"read",        required_argument,  NULL,   'r' },
        {"write",       required_argument,  NULL,   'w' },
        {"address",     required_argument,  NULL,   'a' },
        {"verbose",     no_argument,        NULL,   'v' },
        {"help",        no_argument,        NULL,   'h' },
        {0, 0, 0, 0}
};

static void help()
{
    printf("Version %s\n", VERSION);
    printf("Parameteres:\n");
    printf("\t m,mode: defines mode of accessing memory, possible options are: 'ibyi' - index by index, 'memcpy' - memcpy functions used\n");
    printf("\t r,read: defines number of bytes to be read from memory, value shall be aligned to 4\n");
    printf("\t r,read: defines list of bytes to be written to memory, list length shall be aligned to 4\n");
    printf("\t a,address: defines address in memory from reading or writing shall start with\n");
    printf("\t v,verbose: defines verbosity level\n");
    printf("\t h, help: prints help\n");
    printf("Examples:\n");
    printf("\t data-xfers-test-app -r 64 -a 0xFF200000 -m \"memcpy\"\n");
    printf("\t data-xfers-test-app -w \"0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x3C\" -a 0xFF200000 -m \"memcpy\"\n");
}

char data_str_buffer[512];
static bool parse_data(const char * const  optarg, uint8_t data[], size_t *len)
{
    size_t input_str_len = strlen(optarg);
    char *byte_str;
    size_t index = 0;

    if (input_str_len >= sizeof(data_str_buffer))
    {
        input_str_len = sizeof(data_str_buffer) - 1;
    }
    memcpy(data_str_buffer, optarg, input_str_len);
    data_str_buffer[input_str_len] = 0;

    byte_str = strtok(data_str_buffer, ",");
    while(byte_str != NULL)
    {
        data[index++] = (uint8_t)strtol(byte_str, NULL, 0);
        byte_str = strtok(NULL, ",");
    }

    if (index > 0)
    {
        *len = index;
        return true;
    }
    else
    {
        return false;
    }
}

int main(int argc, char* argv[])
{
    uint8_t data[MAX_DATA_LENGTH_IN_BYTES] = {0};
    uint32_t address = 0x00000000;
    size_t write_length = 0;
    size_t read_length = 0;
    bool do_write = false;
    bool do_read = false;
    char* mode = NULL;
    int verbose = 0;
    int opt;

    void *map_base, *virt_addr;
    int mem_fd;

    while ((opt = getopt_long(argc, argv,  sopts, lopts, NULL)) != EOF)
    {
        switch (opt)
        {
        case 'h':
            help();
            return 0;
        case 'm':
            mode = optarg;
            break;
        case 'r':
            read_length = (size_t)strtol(optarg, NULL, 0);
            if (read_length > MAX_DATA_LENGTH_IN_BYTES)
            {
                printf("Provided read length (%i) exceeded maximum value (%i)\n",
                       read_length, MAX_DATA_LENGTH_IN_BYTES);
                return -1;
            }
            if (read_length > 0)
            {
                do_read = true;
            }
            break;
        case 'w':
            do_write = parse_data(optarg, data, &write_length);
            break;
        case 'a':
            address = strtoul(optarg, NULL, 0);
            break;
        case 'v':
            verbose++;
            break;
        default:
            help();
            return -1;
        }
    }

    if (mode == NULL)
    {
        printf("Access method not provided\n");
        return -1;
    }

    if (write_length % 4 != 0)
    {
        printf("Write length is not aliged to 4: %i\n", write_length);
        write_length = (write_length/4) * 4;
    }

    if (read_length % 4 != 0)
    {
        printf("Read length is not aliged to 4: %i\n", read_length);
        read_length = (read_length/4) * 4;
    }

    if (do_write)
    {
        size_t i;
        printf("Writing data length: %i\n", write_length);
        printf("Data= ");
        for (i = 0; i < write_length; ++i)
        {
            printf("0x%X ", data[i]);
        }
        printf("\n");
    }

    if (do_read)
    {
        printf("Reading data length: %i\n", read_length);
    }

    if (!do_write && !do_read)
    {
        return 0;
    }

    printf("Address: 0x%X\n", address);

    mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0)
    {
        printf("Failed to open '/dev/mem'\n");
        return -1;
    }

    /* Map one page */
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)(address & ~MAP_MASK));
    if (map_base == (void *)-1)
    {
        printf("Failed to map");
        goto err_mem_openeded;
    }
    printf("Memory mapped at address %p.\n", map_base);

    virt_addr = map_base + (address & MAP_MASK);

    if (strncmp(mode, "ibyi", sizeof("ibyi")) == 0)
    {
        size_t i;
        uint32_t *mem_buf = (uint32_t*)virt_addr;
        uint32_t *local_buf = (uint32_t*)&data[0];

        printf("Running 'Index by Index' method.\n");
        if (do_write)
        {
            printf("Writing...\n");
            for (i = 0; i < write_length; i += 4)
            {
                mem_buf[i/4] = local_buf[i/4];
            }
            printf("Done\n");
        }
        if (do_read)
        {
            uint32_t val;

            printf("Reading...\n");
            for (i = 0; i < read_length; i += 4)
            {
                val = mem_buf[i/4];
                printf("0x%X 0x%X 0x%X 0x%X ", val & 0xFF, (val >> 8) & 0xFF,
                       (val >> 16) & 0xFF, (val >> 24) & 0xFF);
            }
            printf("\nDone\n");
        }
    }
    else if (strncmp(mode, "memcpy", sizeof("memcpy")) == 0)
    {
        printf("Running 'memcpy' method.\n");
        if (do_write)
        {
            printf("Writing...\n");
            memcpy(virt_addr, data, write_length);
            printf("Done\n");
        }
        if (do_read)
        {
            size_t i;
            uint8_t val[read_length];

            printf("Reading...\n");
            memcpy(val, virt_addr, read_length);
            for (i = 0; i < read_length; ++i)
            {
                printf("0x%X ", val[i]);
            }
            printf("\nDone\n");
        }
    }
    else if (strncmp(mode, "dma", sizeof("dma")) == 0)
    {
        printf("Not supported\n");
        return -1;
    }
    else
    {
        printf("No access method chosen\n");
    }

    munmap(map_base, MAP_SIZE);
err_mem_openeded:
    close(mem_fd);

    return 0;
}


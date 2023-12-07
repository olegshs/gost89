#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include "gost89.h"

#if _MSC_VER
    #define strcasecmp strcmpi

    char *basename(char *path) {
        int i;
        for (i = strlen(path) - 1; i >= 0; i--) {
            if (path[i] == '/' || path[i] == '\\') {
                return path + i + 1;
            }
        }
        return path;
    }
#else
    #include <libgen.h>
#endif

#define IO_BUFSIZE 65536

const int OPERATION_NONE = 0;
const int OPERATION_ENCRYPT = 1;
const int OPERATION_DECRYPT = 2;
const int OPERATION_MAC = 3;

const int MODE_ECB = 1;
const int MODE_CTR = 2;
const int MODE_CFB = 3;

static gost89_context ctx;

long filesize(FILE *f) {
    long size, pos;

    pos = ftell(f);
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, pos, SEEK_SET);

    return size;
}

int load_sbox(char *sbox_filename) {
    FILE *f;
    long size;
    size_t read;
    char buffer[128];
    int i;

    f = fopen(sbox_filename, "rb");
    if (!f) {
        fprintf(stderr, "Unable to open s-box file: %s\n", sbox_filename);
        return 0;
    }

    size = filesize(f);
    if (size != 128) {
        fprintf(stderr, "Invalid s-box file: %s\n", sbox_filename);
        return 0;
    }

    read = fread(buffer, 1, 128, f);
    if (read != 128) {
        fprintf(stderr, "Unable to read s-box file: %s\n", sbox_filename);
        return 0;
    }

    for (i = 0; i < 128; i++) {
        ctx.sbox[i / 16][i % 16] = buffer[i] % 16;
    }

    gost89_expand_sbox(ctx.sbox, ctx.sbox_x);

    return 1;
}

void print_sbox() {
    int i, j;

    printf("S-Box:\t");
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            printf("%d ", ctx.sbox[i][j]);
        }
        if (i < 7) {
            printf("\n\t");
        }
    }
    printf("\n");
}

int load_key(char *key_filename) {
    FILE *f;
    long size;
    size_t read;

    f = fopen(key_filename, "rb");
    if (!f) {
        fprintf(stderr, "Unable to open key file: %s\n", key_filename);
        return 0;
    }

    size = filesize(f);
    if (size != 32) {
        fprintf(stderr, "Invalid key file: %s\n", key_filename);
        return 0;
    }

    read = fread(ctx.key, 1, sizeof(ctx.key), f);
    if (read != sizeof(ctx.key)) {
        fprintf(stderr, "Unable to read key file: %s\n", key_filename);
        return 0;
    }

    return 1;
}

void print_key() {
    int i;

    printf("Key:\t");
    for (i = 0; i < 8; i++) {
        printf("%08x ", ctx.key[i]);
    }
    printf("\n");
}

int parse_iv(char *iv_str) {
    sscanf(iv_str, "%16llx", (uint64_t*)ctx.iv);

    return 1;
}

void print_iv() {
    int i;

    printf("IV:\t%016llx\n", *((uint64_t*)ctx.iv));
}

static int prev_progress = -1;

void print_progress(long done, long total) {
    int progress = (int)((float)done / (float)total * 100);

    if (progress > prev_progress) {
        printf("\r%d%%", progress);
        fflush(stdout);

        prev_progress = progress;
    }
}

int encrypt_file_ecb(FILE *in, FILE *out, long size, int enable_mac) {
    long offset, length;
    char buffer[IO_BUFSIZE];

    for (offset = 0; offset < size; offset += IO_BUFSIZE) {
        length = size - offset;
        if (length > IO_BUFSIZE) {
            length = IO_BUFSIZE;
        } else {
            unsigned i;
            for (i = length; i < IO_BUFSIZE; i++) {
                buffer[i] = '\0';
            }
        }

        print_progress(offset, size);

        fread(buffer, 1, length, in);

        if (enable_mac) {
            gost89_mac(&ctx, buffer, length);
        }

        gost89_encrypt_ecb(&ctx, buffer, buffer, length);

        fwrite(buffer, 1, length, out);
    }

    return 1;
}

int decrypt_file_ecb(FILE *in, FILE *out, long size, int enable_mac) {
    long offset, length;
    char buffer[IO_BUFSIZE];

    for (offset = 0; offset < size; offset += IO_BUFSIZE) {
        length = size - offset;
        if (length > IO_BUFSIZE) {
            length = IO_BUFSIZE;
        } else {
            unsigned i;
            for (i = length; i < IO_BUFSIZE; i++) {
                buffer[i] = '\0';
            }
        }

        print_progress(offset, size);

        fread(buffer, 1, length, in);

        gost89_decrypt_ecb(&ctx, buffer, buffer, length);

        if (enable_mac) {
            gost89_mac(&ctx, buffer, length);
        }

        fwrite(buffer, 1, length, out);
    }

    return 1;
}

int encrypt_file_ctr(FILE *in, FILE *out, long size, int enable_mac) {
    long offset, length;
    char buffer[IO_BUFSIZE];

    gost89_init_ctr(&ctx);

    for (offset = 0; offset < size; offset += IO_BUFSIZE) {
        length = size - offset;
        if (length > IO_BUFSIZE) {
            length = IO_BUFSIZE;
        } else {
            unsigned i;
            for (i = length; i < IO_BUFSIZE; i++) {
                buffer[i] = '\0';
            }
        }

        print_progress(offset, size);

        fread(buffer, 1, length, in);

        if (enable_mac) {
            gost89_mac(&ctx, buffer, length);
        }

        gost89_encrypt_ctr(&ctx, buffer, buffer, length);

        fwrite(buffer, 1, length, out);
    }

    return 1;
}

int decrypt_file_ctr(FILE *in, FILE *out, long size, int enable_mac) {
    long offset, length;
    char buffer[IO_BUFSIZE];

    gost89_init_ctr(&ctx);

    for (offset = 0; offset < size; offset += IO_BUFSIZE) {
        length = size - offset;
        if (length > IO_BUFSIZE) {
            length = IO_BUFSIZE;
        } else {
            unsigned i;
            for (i = length; i < IO_BUFSIZE; i++) {
                buffer[i] = '\0';
            }
        }

        print_progress(offset, size);

        fread(buffer, 1, length, in);

        gost89_encrypt_ctr(&ctx, buffer, buffer, length);

        if (enable_mac) {
            gost89_mac(&ctx, buffer, length);
        }

        fwrite(buffer, 1, length, out);
    }

    return 1;
}

int encrypt_file_cfb(FILE *in, FILE *out, long size, int enable_mac) {
    long offset, length;
    char buffer[IO_BUFSIZE];

    for (offset = 0; offset < size; offset += IO_BUFSIZE) {
        length = size - offset;
        if (length > IO_BUFSIZE) {
            length = IO_BUFSIZE;
        } else {
            unsigned i;
            for (i = length; i < IO_BUFSIZE; i++) {
                buffer[i] = '\0';
            }
        }

        print_progress(offset, size);

        fread(buffer, 1, length, in);

        if (enable_mac) {
            gost89_mac(&ctx, buffer, length);
        }

        gost89_encrypt_cfb(&ctx, buffer, buffer, length);

        fwrite(buffer, 1, length, out);
    }

    return 1;
}

int decrypt_file_cfb(FILE *in, FILE *out, long size, int enable_mac) {
    long offset, length;
    char buffer[IO_BUFSIZE];

    for (offset = 0; offset < size; offset += IO_BUFSIZE) {
        length = size - offset;
        if (length > IO_BUFSIZE) {
            length = IO_BUFSIZE;
        } else {
            unsigned i;
            for (i = length; i < IO_BUFSIZE; i++) {
                buffer[i] = '\0';
            }
        }

        print_progress(offset, size);

        fread(buffer, 1, length, in);

        gost89_decrypt_cfb(&ctx, buffer, buffer, length);

        if (enable_mac) {
            gost89_mac(&ctx, buffer, length);
        }

        fwrite(buffer, 1, length, out);
    }

    return 1;
}

void print_mac() {
    printf("\nMAC:\t%08x\n", ctx.mac[1]);
}

int file_mac(char *in_filename) {
    FILE *in;
    long size;
    long offset, length;
    char buffer[IO_BUFSIZE];

    in = fopen(in_filename, "rb");
    if (!in) {
        fprintf(stderr, "Unable to open file for reading: %s\n", in_filename);
        return 0;
    }

    size = filesize(in);
    if (!size) {
        fprintf(stderr, "Empty file: %s", in_filename);
        return 0;
    }

    gost89_set_mac(&ctx, NULL);

    for (offset = 0; offset < size; offset += IO_BUFSIZE) {
        length = size - offset;
        if (length > IO_BUFSIZE) {
            length = IO_BUFSIZE;
        } else {
            unsigned i;
            for (i = length; i < IO_BUFSIZE; i++) {
                buffer[i] = '\0';
            }
        }

        print_progress(offset, size);

        fread(buffer, 1, length, in);

        gost89_mac(&ctx, buffer, length);
    }

    fclose(in);

    printf("\rDone.\n");
    print_mac();

    return 1;
}

int process_file(char *in_filename, char *out_filename, int operation, int mode, int enable_mac) {
    FILE *in, *out;
    long size;

    in = fopen(in_filename, "rb");
    if (!in) {
        fprintf(stderr, "Unable to open file for reading: %s\n", in_filename);
        return 0;
    }

    size = filesize(in);
    if (!size) {
        fprintf(stderr, "Empty file: %s", in_filename);
        return 0;
    }

    out = fopen(out_filename, "wb");
    if (!out) {
        fprintf(stderr, "Unable to open file for writing: %s\n", out_filename);
        return 0;
    }

    if (enable_mac) {
        gost89_set_mac(&ctx, NULL);
    }

    if (mode == MODE_ECB) {
        if (size % 8) {
            fprintf(stderr, "File size must be a multiple of 8 bytes: %s\n", in_filename);
            return 0;
        }

        if (operation == OPERATION_ENCRYPT) {
            encrypt_file_ecb(in, out, size, enable_mac);
        } else {
            decrypt_file_ecb(in, out, size, enable_mac);
        }
    } else if (mode == MODE_CTR) {
        if (operation == OPERATION_ENCRYPT) {
            encrypt_file_ctr(in, out, size, enable_mac);
        } else {
            decrypt_file_ctr(in, out, size, enable_mac);
        }
    } else if (mode == MODE_CFB) {
        if (operation == OPERATION_ENCRYPT) {
            encrypt_file_cfb(in, out, size, enable_mac);
        } else {
            decrypt_file_cfb(in, out, size, enable_mac);
        }
    }

    fclose(in);
    fclose(out);

    printf("\rDone.\n");

    if (enable_mac) {
        print_mac();
    }

    return 1;
}

int main(int argc, char **argv) {
    int c, i;
    int option_index = 0;
    int operation = OPERATION_NONE;
    int enable_mac = 0;
    int mode = MODE_CTR;
    char *key_file = NULL, *sbox_file = NULL, *iv_str = NULL;
    char *in_file = NULL, *out_file = NULL;
    const char *operation_str = NULL, *mode_str = NULL;
    const char *file_ext_encrypted = ".gost", *file_ext_plain = ".plain";
    struct option long_options[] = {
        {"encrypt", no_argument,       0, 'e'},
        {"decrypt", no_argument,       0, 'd'},
        {"mac",     no_argument,       0, 'a'},
        {"mode",    required_argument, 0, 'm'},
        {"sbox",    required_argument, 0, 's'},
        {"key",     required_argument, 0, 'k'},
        {"iv",      required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    opterr = 0;
    while ((c = getopt_long(argc, argv, "edam:s:k:i:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'e':
                operation = OPERATION_ENCRYPT;
                break;
            case 'd':
                operation = OPERATION_DECRYPT;
                break;
            case 'a':
                if (operation == OPERATION_NONE) {
                    operation = OPERATION_MAC;
                }
                enable_mac = 1;
                break;
            case 'm':
                if (!strcasecmp(optarg, "ecb")) {
                    mode = MODE_ECB;
                } else if (!strcasecmp(optarg, "ctr")) {
                    mode = MODE_CTR;
                } else if (!strcasecmp(optarg, "cfb")) {
                    mode = MODE_CFB;
                }
                break;
            case 'k':
                key_file = optarg;
                break;
            case 's':
                sbox_file = optarg;
                break;
            case 'i':
                iv_str = optarg;
                break;
            case '?':
                if (optopt == 'm' || optopt == 's' || optopt == 'k' || optopt == 'i') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else if (isprint(optopt)) {
                    fprintf(stderr, "Unknown option -%c\n", optopt);
                } else {
                    fprintf(stderr, "Unknown option character \\x%x\n", optopt);
                }
                return 1;
            default:
                abort();
        }
    }

    if (argc > optind) {
        in_file = argv[optind];
    } else {
        fprintf(stderr, "Usage: %s [-edamski] in_file [out_file]\n", basename(argv[0]));
        return 1;
    }

    if (argc > optind + 1) {
        out_file = argv[optind + 1];
    } else if (operation != OPERATION_MAC) {
        if (operation == OPERATION_ENCRYPT) {
            out_file = (char*)malloc(strlen(in_file) + 6);
            strcpy(out_file, in_file);
            strcat(out_file, file_ext_encrypted);
        } else {
            if (!strcasecmp(in_file + strlen(in_file) - 5, file_ext_encrypted)) {
                out_file = (char*)malloc(strlen(in_file));
                strcpy(out_file, in_file);
                out_file[strlen(out_file) - 5] = '\0';
            } else {
                out_file = (char*)malloc(strlen(in_file) + 7);
                strcpy(out_file, in_file);
                strcat(out_file, file_ext_plain);
            }
        }
    }

    if (!(sbox_file && load_sbox(sbox_file))) {
        for (i = 0; i < 128; i++) {
            ctx.sbox[i / 16][i % 16] = i % 16;
        }
    }
    print_sbox();

    if (!(key_file && load_key(key_file))) {
        for (i = 0; i < 8; i++) {
            ctx.key[i] = 0;
        }
    }
    print_key();

    if (mode != MODE_ECB && operation != OPERATION_MAC) {
        if (!(iv_str && parse_iv(iv_str))) {
            gost89_set_iv(&ctx, NULL);
        }
        print_iv();
    }

    printf("\n");

    if (operation == OPERATION_MAC) {
        printf("Calculating MAC: %s\n", in_file);
        file_mac(in_file);
    } else {
        if (operation == OPERATION_ENCRYPT) {
            operation_str = "Encrypting";
        } else {
            operation_str = "Decrypting";
        }

        if (mode == MODE_ECB) {
            mode_str = "ECB";
        } else if (mode == MODE_CFB) {
            mode_str = "CFB";
        } else {
            mode_str = "CTR";
        }

        printf("%s in %s mode: %s -> %s\n", operation_str, mode_str, in_file, out_file);
        process_file(in_file, out_file, operation, mode, enable_mac);
    }

    return 0;
}

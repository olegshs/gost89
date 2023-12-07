#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "gost89.h"

/*
static uint8_t test_sbox[8][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
};
*/

static uint8_t test_sbox[8][16] = {
    {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
    {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
    {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
    {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
    {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
    {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
    {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
    {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12},
};

static char *test_key = "01234567890123456789012345678912";
static char *test_iv = "\xFF\x00\x00\x00\x00\x00\x00\x00";

static gost89_context ctx;

long filesize(FILE *f) {
    long p, s;
    p = ftell(f);

    fseek(f, 0, SEEK_END);
    s = ftell(f);
    fseek(f, p, SEEK_SET);

    return s;
}

void test() {
    int i;
    char plain[8], encrypted[8];

    gost89_set_key(&ctx, test_key);

    memcpy(plain, "ABCDEFGH", 8);
    for (i = 0; i < 8; i++) {
        printf("%02x ", plain[i] & 0xFF);
    }
    puts("");

    gost89_encrypt(&ctx, plain, encrypted);

    for (i = 0; i < 8; i++) {
        printf("%02x ", encrypted[i] & 0xFF);
    }
    puts("");

    gost89_decrypt(&ctx, encrypted, plain);
    for (i = 0; i < 8; i++) {
        printf("%02x ", plain[i] & 0xFF);
    }
    puts("");
}

void benchmark() {
    int i;
    clock_t t0, t1;
    char a[8], b[8];

    gost89_set_key(&ctx, test_key);
    memcpy(a, "ABCDEFGH", 8);

    t0 = clock();
    for (i = 0; i < 5000000; i++) {
        gost89_encrypt(&ctx, a, b);
        gost89_encrypt(&ctx, b, a);
    }
    for (i = 0; i < 5000000; i++) {
        gost89_decrypt(&ctx, a, b);
        gost89_decrypt(&ctx, b, a);
    }
    t1 = clock();

    for (i = 0; i < 8; i++) {
        printf("%02x ", a[i]);
    }
    puts("");

    printf("%f\n", (float)(t1 - t0) / CLOCKS_PER_SEC);
}

void error_open_read(const char *filename) {
    fprintf(stderr, "Unable to open file for reading: %s\n", filename);
}

void error_open_write(const char *filename) {
    fprintf(stderr, "Unable to open file for writing: %s\n", filename);
}

void test_encrypt_ecb() {
    long i, n;
    FILE *in, *out;
    char buffer[65536];

    in = fopen("test.txt", "rb");
    if (!in) {
        error_open_read("test.txt");
        return;
    }

    n = filesize(in);
    fread(buffer, 1, n, in);
    buffer[n] = '\0';

    gost89_set_key(&ctx, test_key);

    out = fopen("test.ecb.1", "wb");
    if (!out) {
        error_open_write("test.ecb.1");
        return;
    }

    gost89_encrypt_ecb(&ctx, buffer, buffer, n);

    fwrite(buffer, 1, n, out);

    fclose(in);
    fclose(out);
}

void test_decrypt_ecb() {
    long i, n;
    FILE *in, *out;
    char buffer[65536];

    in = fopen("test.ecb.1", "rb");
    if (!in) {
        error_open_read("test.ecb.1");
        return;
    }

    n = filesize(in);
    fread(buffer, 1, n, in);
    buffer[n] = '\0';

    gost89_set_key(&ctx, test_key);

    out = fopen("test.ecb.2", "wb");
    if (!out) {
        error_open_write("test.ecb.2");
        return;
    }

    gost89_decrypt_ecb(&ctx, buffer, buffer, n);

    fwrite(buffer, 1, n, out);

    fclose(in);
    fclose(out);
}

void test_encrypt_ctr() {
    long i, n;
    FILE *in, *out;
    char buffer[65536];

    in = fopen("test.txt", "rb");
    if (!in) {
        error_open_read("test.txt");
        return;
    }

    n = filesize(in);
    fread(buffer, 1, n, in);
    buffer[n] = '\0';

    gost89_set_key(&ctx, test_key);

    gost89_set_iv(&ctx, test_iv);
    printf("%08x %08x\n", ctx.iv[1], ctx.iv[0]);

    out = fopen("test.ctr.1", "wb");
    if (!out) {
        error_open_write("test.ctr.1");
        return;
    }

    gost89_init_ctr(&ctx);
    gost89_encrypt_ctr(&ctx, buffer, buffer, n);

    fwrite(buffer, 1, n, out);

    fclose(in);
    fclose(out);
}

void test_decrypt_ctr() {
    long i, n;
    FILE *in, *out;
    char buffer[65536];

    in = fopen("test.ctr.1", "rb");
    if (!in) {
        error_open_read("test.ctr.1");
        return;
    }

    n = filesize(in);
    fread(buffer, 1, n, in);
    buffer[n] = '\0';

    gost89_set_key(&ctx, test_key);

    gost89_set_iv(&ctx, test_iv);
    printf("%08x %08x\n", ctx.iv[1], ctx.iv[0]);

    out = fopen("test.ctr.2", "wb");
    if (!out) {
        error_open_write("test.ctr.2");
        return;
    }

    gost89_init_ctr(&ctx);
    gost89_encrypt_ctr(&ctx, buffer, buffer, n);

    fwrite(buffer, 1, n, out);

    fclose(in);
    fclose(out);
}

void test_encrypt_cfb() {
    long i, n;
    FILE *in, *out;
    char buffer[65536];

    in = fopen("test.txt", "rb");
    if (!in) {
        error_open_read("test.txt");
        return;
    }

    n = filesize(in);
    fread(buffer, 1, n, in);
    buffer[n] = '\0';

    gost89_set_key(&ctx, test_key);

    gost89_set_iv(&ctx, test_iv);
    printf("%08x %08x\n", ctx.iv[1], ctx.iv[0]);

    out = fopen("test.cfb.1", "wb");
    if (!out) {
        error_open_write("test.cfb.1");
        return;
    }

    gost89_encrypt_cfb(&ctx, buffer, buffer, n);

    fwrite(buffer, 1, n, out);

    fclose(in);
    fclose(out);
}

void test_decrypt_cfb() {
    long i, n;
    FILE *in, *out;
    char buffer[65536];

    in = fopen("test.cfb.1", "rb");
    if (!in) {
        error_open_read("test.cfb.1");
        return;
    }

    n = filesize(in);
    fread(buffer, 1, n, in);
    buffer[n] = '\0';

    gost89_set_key(&ctx, test_key);

    gost89_set_iv(&ctx, test_iv);
    printf("%08x %08x\n", ctx.iv[1], ctx.iv[0]);

    out = fopen("test.cfb.2", "wb");
    if (!out) {
        error_open_write("test.cfb.2");
        return;
    }

    gost89_decrypt_cfb(&ctx, buffer, buffer, n);

    fwrite(buffer, 1, n, out);

    fclose(in);
    fclose(out);
}

void test_mac() {
    long i, n;
    FILE *in, *out;
    char buffer[65536];

    in = fopen("test.txt", "rb");
    if (!in) {
        error_open_read("test.txt");
        return;
    }

    n = filesize(in);
    fread(buffer, 1, n, in);
    buffer[n] = '\0';

    gost89_set_key(&ctx, test_key);
    gost89_set_mac(&ctx, NULL);

    gost89_mac(&ctx, buffer, n);

    printf("%08x %08x\n", ctx.mac[0], ctx.mac[1]);
}

int main(int argc, char **argv) {
    gost89_set_sbox(&ctx, test_sbox);

    test();
    test_mac();
    test_encrypt_ecb();
    test_decrypt_ecb();
    test_encrypt_ctr();
    test_decrypt_ctr();
    test_encrypt_cfb();
    test_decrypt_cfb();
    benchmark();

    return 0;
}

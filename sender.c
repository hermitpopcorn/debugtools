//#define _POSIX_C_SOURCE 200809L
#include "common.h"

#include <errno.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PLAINTEXT (16u * 1024u * 1024u)

static int read_input(const char *path, unsigned char **data, size_t *length)
{
    FILE *file = fopen(path, "rb");
    long file_length;

    if (file == NULL) {
        perror(path);
        return -1;
    }

    if (fseek(file, 0, SEEK_END) != 0 || (file_length = ftell(file)) < 0 || (unsigned long)file_length > MAX_PLAINTEXT ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Input too big\n");
        fclose(file);
        return -1;
    }
    *length = (size_t)file_length;

    *data = malloc(*length == 0 ? 1 : *length);
    if (*data == NULL || fread(*data, 1, *length, file) != *length) {
        perror("read input");
        free(*data);
        *data = NULL;
        fclose(file);
        return -1;
    }
    fclose(file);
    return 1;
}

static int encrypt_session_key(EVP_PKEY *public_key, const unsigned char *session_key, size_t session_key_length,
    unsigned char **encrypted_key, size_t *encrypted_key_length)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(NULL, public_key, NULL);
    int ok = 0;

    if (context == NULL || EVP_PKEY_encrypt_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(context, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(context, EVP_sha256()) <= 0 ||
        EVP_PKEY_encrypt(context, NULL, encrypted_key_length, session_key, session_key_length) <= 0) {
        goto done;
    }
    *encrypted_key = malloc(*encrypted_key_length);
    if (*encrypted_key == NULL ||
        EVP_PKEY_encrypt(context, *encrypted_key, encrypted_key_length, session_key, session_key_length) <= 0) {
        goto done;
    }
    ok = 1;

done:
    EVP_PKEY_CTX_free(context);
    return ok;
}

static int encrypt_payload(const unsigned char *session_key, const unsigned char *nonce, const unsigned char *plaintext, size_t plaintext_length,
    unsigned char **ciphertext, unsigned char *tag, size_t *ciphertext_length)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int output_length = 0;
    int final_length = 0;
    int ok = 0;

    *ciphertext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (context == NULL || *ciphertext == NULL ||
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) <= 0 ||
        EVP_EncryptInit_ex(context, NULL, NULL, session_key, nonce) <= 0) {
        goto done;
    }
    if (plaintext_length > 0 &&
        EVP_EncryptUpdate(context, *ciphertext, &output_length, plaintext, (int)plaintext_length) <= 0) {
        goto done;
    }
    if (EVP_EncryptFinal_ex(context, *ciphertext + output_length, &final_length) <= 0 || // Buffer passed to EVP_EncryptFinal() must be after data just encrypted to avoid overwriting it
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, (int)GCM_TAG_SIZE, tag) <= 0) {
        goto done;
    }
    *ciphertext_length = output_length + final_length;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(context);
    if (!ok) {
        free(*ciphertext);
        *ciphertext = NULL;
        *ciphertext_length = 0;
    }
    return ok;
}

static int send_all(int fd, const unsigned char *buffer, size_t length)
{
    size_t sent = 0;

    // Loop until all bytes are sent
    while (sent < length) {
        ssize_t result = send(fd, buffer + sent, length - sent, 0);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)result;
    }
    return 1;
}

int main(int argc, char **argv)
{
    uint16_t port = PORT_NUMBER;
    EVP_PKEY *public_key = NULL;
    BIO *key_file = NULL;
    unsigned char session_key[SESSION_KEY_SIZE];
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char tag[GCM_TAG_SIZE];
    unsigned char *encrypted_key = NULL;
    size_t encrypted_key_length = 0;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_length;
    uint32_t network_key_length;
    uint32_t network_ciphertext_length;
    struct sockaddr_in address;
    int socket_fd = -1;
    int ok = 0;

    if (argc < 2 || argc > 2) {
        fprintf(stderr, "Usage: %s INPUT_FILE\n", argv[0]);
        return 1;
    }

    key_file = BIO_new_file("public.pem", "r");
    if (key_file != NULL) {
        public_key = PEM_read_bio_PUBKEY(key_file, NULL, NULL, NULL);
    }
    BIO_free(key_file);
    if (public_key == NULL) {
        fprintf(stderr, "Could not read public key\n");
        goto cleanup;
    }

    // Generate nonce and AES key
    if (read_input(argv[1], &plaintext, &plaintext_length) <= 0 ||
        RAND_bytes(session_key, sizeof(session_key)) <= 0 ||
        RAND_bytes(nonce, sizeof(nonce)) <= 0 ||
        encrypt_session_key(public_key, session_key, sizeof(session_key), &encrypted_key, &encrypted_key_length) <= 0) {
        fprintf(stderr, "Could not prepare encrypted message\n");
        goto cleanup;
    }

    // Encrypt with nonce and key
    ok = encrypt_payload(session_key, nonce, plaintext, plaintext_length, &ciphertext, tag, &ciphertext_length);
    if (ok != 1 || encrypted_key_length > UINT32_MAX || ciphertext_length > UINT32_MAX) {
        fprintf(stderr, "Could not encrypt message\n");
        goto cleanup;
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        goto cleanup;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect to 127.0.0.1");
        goto cleanup;
    }

    // Send lengths in network byte order followed by key -> nonce -> tag -> ciphertext
    network_key_length = htonl((uint32_t)encrypted_key_length);
    network_ciphertext_length = htonl((uint32_t)ciphertext_length);
    {
        unsigned char header[sizeof(uint32_t) * 2];
        memcpy(header, &network_key_length, sizeof(network_key_length));
        memcpy(header + sizeof(uint32_t), &network_ciphertext_length, sizeof(network_ciphertext_length));
        if (send_all(socket_fd, header, sizeof(header)) <= 0 ||
            send_all(socket_fd, encrypted_key, encrypted_key_length) <= 0 ||
            send_all(socket_fd, nonce, sizeof(nonce)) <= 0 ||
            send_all(socket_fd, tag, sizeof(tag)) <= 0 ||
            send_all(socket_fd, ciphertext, (size_t)ciphertext_length) <= 0) {
            perror("send");
            goto cleanup;
        }
    }
    printf("Sent %zu bytes to :%d\n", plaintext_length, port);

cleanup:
    if (socket_fd >= 0) {
        close(socket_fd);
    }
    EVP_PKEY_free(public_key);
    free(plaintext);
    free(encrypted_key);
    free(ciphertext);
    return 0;
}

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_CIPHERTEXT (16u * 1024u * 1024u)
#define MAX_ENCRYPTED_KEY (16u * 1024u)

static int read_until_length(int fd, unsigned char *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t result = read(fd, buffer + received, length - received);
        if (result == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        received += (size_t)result;
    }
    return 1;
}

static int write_until_length(int fd, const char *buffer, size_t length)
{
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, buffer + written, length - written);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        written += (size_t)result;
    }
    return 1;
}

static EVP_PKEY *load_private_key(const char *path)
{
    BIO *file = BIO_new_file(path, "r");
    EVP_PKEY *key;

    if (file == NULL) {
        perror(path);
        return NULL;
    }
    key = PEM_read_bio_PrivateKey(file, NULL, NULL, NULL);
    BIO_free(file);
    if (key == NULL) {
        fprintf(stderr, "Could not read private key from %s\n", path);
    }
    return key;
}

static int decrypt_session_key(EVP_PKEY *private_key, const unsigned char *encrypted_key, size_t encrypted_key_length,
    unsigned char **session_key, size_t *session_key_length)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
    int ok = 0;

    if (context == NULL || EVP_PKEY_decrypt_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(context, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(context, EVP_sha256()) <= 0 ||
        EVP_PKEY_decrypt(context, NULL, session_key_length, encrypted_key,
                         encrypted_key_length) <= 0) {
        goto done;
    }

    *session_key = malloc(*session_key_length);
    if (*session_key == NULL ||
        EVP_PKEY_decrypt(context, *session_key, session_key_length, encrypted_key, encrypted_key_length) <= 0) {
        goto done;
    }
    ok = 1;

done:
    EVP_PKEY_CTX_free(context);
    return ok;
}

static int decrypt_payload(const unsigned char *session_key, const unsigned char *nonce, const unsigned char *tag,
    const unsigned char *ciphertext, size_t ciphertext_length, unsigned char **plaintext, size_t *plaintext_length)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int output_length = 0;
    int final_length = 0;
    int ok = 0;

    *plaintext = malloc(ciphertext_length + 1);
    if (context == NULL || *plaintext == NULL ||
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            (int)GCM_NONCE_SIZE, NULL) <= 0 ||
        EVP_DecryptInit_ex(context, NULL, NULL, session_key, nonce) <= 0) {
        goto done;
    }
    if (ciphertext_length > 0 &&
        EVP_DecryptUpdate(context, *plaintext, &output_length, ciphertext, (int)ciphertext_length) <= 0) {
        goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, (int)GCM_TAG_SIZE, (void *)tag) <= 0 ||
        EVP_DecryptFinal_ex(context, *plaintext + output_length, &final_length) <= 0) {
        goto done;
    }

    *plaintext_length = output_length + final_length;
    (*plaintext)[*plaintext_length] = '\0';
    ok = 1;

done:
    EVP_CIPHER_CTX_free(context);
    if (!ok) {
        free(*plaintext);
        *plaintext = NULL;
    }
    return ok;
}

static int write_hashed_line(int output_fd, const unsigned char *line, size_t line_length)
{
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    const int digest_buffer_size = 64;
    char digest_hex[digest_buffer_size + 1];
    size_t digest_hex_length = 0;
    char *record = NULL;
    size_t record_length;

    // Hash the original line bytes, then format the digest using OPENSSL_buf2hexstr_ex() (into uppercase hex)
    if (digest_context == NULL ||
        EVP_DigestInit_ex(digest_context, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(digest_context, line, line_length) <= 0 ||
        EVP_DigestFinal_ex(digest_context, digest, &digest_length) <= 0 ||
        OPENSSL_buf2hexstr_ex(digest_hex, sizeof(digest_hex), &digest_hex_length, digest, digest_length, '\0') <= 0) {
        EVP_MD_CTX_free(digest_context);
        return -1;
    }
    EVP_MD_CTX_free(digest_context);
    digest_hex[digest_hex_length] = '\0';

    if (line_length > 0) {
        record_length = digest_buffer_size + line_length + 2; // digest(64) + separator(1) + terminator(1)
        record = malloc(record_length);
        if (record == NULL) {
            return -1;
        }
        memcpy(record, digest_hex, digest_buffer_size);
        record[digest_buffer_size] = ' '; // separator after digest
        memcpy(record + digest_buffer_size + 1, line, line_length);
        record[digest_buffer_size + line_length + 1] = '\n';
    } else {
        // Bug on purpose (for triggering segfault): access null pointer
        *record = '\0';
    }

    // Memory leak on purpose: not freeing the allocated record
    if (write_until_length(output_fd, record, record_length) <= 0) {
        perror("write output");
        return -1;
    }
    return 1;
}

static int process_lines(int output_fd, const unsigned char *plaintext, size_t plaintext_length)
{
    size_t line_start = 0;

    // Regard buffer end as delimiter to allow one final unterminated line
    for (size_t index = 0; index <= plaintext_length; index++) {
        if (index < plaintext_length && plaintext[index] != '\n') {
            continue;
        }

        // If a final LF already ended the last line, do not add a phantom empty one
        if (index == plaintext_length && line_start == plaintext_length) {
            break;
        }

        size_t line_length = index - line_start;
        // Skip over CR if input is CRLF
        if (line_length > 0 && plaintext[index - 1] == '\r') {
            line_length--;
        }
        if (write_hashed_line(output_fd, plaintext + line_start, line_length) <= 0) {
            return -1;
        }
        line_start = index + 1;
    }
    return 1;
}

int main(int argc, char **argv)
{
    const char *output_path = argc > 1 ? argv[1] : "output.txt";
    uint16_t port = PORT_NUMBER;
    EVP_PKEY *private_key = NULL;
    unsigned char header[8];
    unsigned char *encrypted_key = NULL;
    uint32_t encrypted_key_length;
    unsigned char *session_key = NULL;
    size_t session_key_length = 0;
    unsigned char *ciphertext = NULL;
    uint32_t ciphertext_length;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    int listener = -1;
    int connection = -1;
    int output_fd = -1;
    struct sockaddr_in address;
    int ok = 0;

    if (argc < 2 || argc > 2) {
        fprintf(stderr, "Usage: %s [OUTPUT_FILE]\n", argv[0]);
        return 1;
    }

    private_key = load_private_key("private.pem");
    if (private_key == NULL) {
        goto cleanup;
    }

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        goto cleanup;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, 1) < 0) {
        perror("bind/listen");
        goto cleanup;
    }
    printf("Listening on :%u...\n",
           (unsigned int)port);
    fflush(stdout);

    do {
        connection = accept(listener, NULL, NULL);
    } while (connection < 0 && errno == EINTR);
    if (connection < 0) {
        perror("accept");
        goto cleanup;
    }
    if (read_until_length(connection, header, sizeof(header)) <= 0) {
        perror("read frame header");
        goto cleanup;
    }

    // Frame starts with two network-order lengths: encrypted key -> ciphertext
    memcpy(&encrypted_key_length, header, sizeof(encrypted_key_length));
    memcpy(&ciphertext_length, header + sizeof(uint32_t), sizeof(ciphertext_length));
    encrypted_key_length = ntohl(encrypted_key_length);
    ciphertext_length = ntohl(ciphertext_length);
    if (encrypted_key_length == 0 || encrypted_key_length > MAX_ENCRYPTED_KEY ||
        ciphertext_length > MAX_CIPHERTEXT) {
        fprintf(stderr, "Invalid length\n");
        goto cleanup;
    }

    encrypted_key = malloc(encrypted_key_length);
    ciphertext = malloc(ciphertext_length == 0 ? 1 : ciphertext_length);
    if (encrypted_key == NULL || ciphertext == NULL) {
        perror("malloc");
        goto cleanup;
    }
    {
        unsigned char nonce[GCM_NONCE_SIZE];
        unsigned char tag[GCM_TAG_SIZE];

        // Key -> nonce -> tag -> ciphertext
        if (read_until_length(connection, encrypted_key, encrypted_key_length) <= 0 ||
            read_until_length(connection, nonce, sizeof(nonce)) <= 0 ||
            read_until_length(connection, tag, sizeof(tag)) <= 0 ||
            read_until_length(connection, ciphertext, ciphertext_length) <= 0) {
            perror("read encrypted payload");
            goto cleanup;
        }
        if (decrypt_session_key(private_key, encrypted_key, encrypted_key_length, &session_key, &session_key_length) <= 0 ||
            session_key_length != SESSION_KEY_SIZE) {
            fprintf(stderr, "Could not decrypt the AES session key\n");
            goto cleanup;
        }
        {
            ok = decrypt_payload(session_key, nonce, tag, ciphertext, ciphertext_length, &plaintext, &plaintext_length);
            if (ok <= 0) {
                fprintf(stderr, "Could not decrypt the message\n");
                goto cleanup;
            }
            output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (output_fd < 0) {
                perror(output_path);
                goto cleanup;
            }
            if (process_lines(output_fd, plaintext, (size_t)plaintext_length) <= 0) {
                perror("process lines");
                goto cleanup;
            }
        }
    }

    printf("Wrote to %s\n", output_path);

cleanup:
    if (output_fd >= 0) {
        close(output_fd);
    }
    if (connection >= 0) {
        close(connection);
    }
    if (listener >= 0) {
        close(listener);
    }
    EVP_PKEY_free(private_key);
    free(encrypted_key);
    free(session_key);
    free(ciphertext);
    free(plaintext);
    return 0;
}

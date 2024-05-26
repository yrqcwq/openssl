#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include<openssl/err.h>
#include <fcntl.h>
#include <signal.h>


#define BUFFER_SIZE 1024
#define RSA_KEY_LENGTH 2048
#define AES_KEY_LENGTH 256
#define AES_BLOCK_SIZE 16
/*
void handleErrors(void)
{
    fprintf(stderr, "Error occurred\n");
    exit(EXIT_FAILURE);
}*/
int server_socket = -1;
void handleErrors(void)
{
    fprintf(stderr, "Error occurred\n");
    exit(EXIT_FAILURE);
}
void cleanup(int signum)
{
    if (server_socket != -1)
    {
        close(server_socket);
        printf("Server socket closed\n");
    }
    exit(EXIT_SUCCESS);
}




void generate_aes_key(unsigned char *key, unsigned char *iv)
{
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0)
    {
        perror("Error opening /dev/urandom");
        exit(EXIT_FAILURE);
    }

    // 读取随机字节到key
    ssize_t bytes_read = read(urandom_fd, key, AES_KEY_LENGTH / 8);
    if (bytes_read != AES_KEY_LENGTH / 8)
    {
        perror("Error reading from /dev/urandom");
        exit(EXIT_FAILURE);
    }

    // 读取随机字节到iv
    bytes_read = read(urandom_fd, iv, AES_BLOCK_SIZE);
    if (bytes_read != AES_BLOCK_SIZE)
    {
        perror("Error reading from /dev/urandom");
        exit(EXIT_FAILURE);
    }

    close(urandom_fd);
}





int main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    unsigned char plaintext[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + AES_BLOCK_SIZE];
    unsigned char aes_key[AES_KEY_LENGTH / 8];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    EVP_PKEY *rsa_key = NULL;

     // Set up signal handling
    signal(SIGINT, cleanup);   // Handle Ctrl+C
    signal(SIGTERM, cleanup);  // Handle termination signal
    signal(SIGHUP,cleanup);
    // Initializing OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);

    // Generating RSA key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LENGTH) <= 0)
        handleErrors();
    if (EVP_PKEY_keygen(ctx, &rsa_key) <= 0)
        handleErrors();
    EVP_PKEY_CTX_free(ctx);

    // Creating socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    // Setting SO_REUSEADDR option
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    // Server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(12349);

    // Binding socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    // Listening for connections
    listen(server_socket, 5);

    // Accepting connections in a loop
    while (1)
    {
        // Accepting connections
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);

        if (client_socket < 0)
        {
            perror("Error accepting connection");
            exit(EXIT_FAILURE);
        }
        // Sending public key to client
        EVP_PKEY *public_key = EVP_PKEY_dup(rsa_key);
        if (!public_key)
            handleErrors();

        BIO *bio_out = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio_out, public_key);
        char *public_key_pem;
        long public_key_pem_len = BIO_get_mem_data(bio_out, &public_key_pem);
        write(client_socket, public_key_pem, public_key_pem_len);
        BIO_free(bio_out);
        EVP_PKEY_free(public_key);

        // Receiving encrypted AES key from client
        size_t encrypted_key_len = read(client_socket, ciphertext, BUFFER_SIZE);
        if (encrypted_key_len < 0)
        {
            perror("Error receiving encrypted key from client");
            exit(EXIT_FAILURE);
        }

        // Decrypting AES key
        unsigned char decrypted_key[AES_KEY_LENGTH / 8];
        EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(rsa_key, NULL);
        if (!decrypt_ctx || EVP_PKEY_decrypt_init(decrypt_ctx) <= 0)
            handleErrors();
        

        size_t decrypted_key_len = AES_KEY_LENGTH / 8;
        if (EVP_PKEY_decrypt(decrypt_ctx, NULL, &decrypted_key_len, ciphertext, encrypted_key_len) <= 0)
            {   
                handleErrors();} 
        if (EVP_PKEY_decrypt(decrypt_ctx, decrypted_key, &decrypted_key_len, ciphertext, encrypted_key_len) <= 0)
            {   
                handleErrors();}       

        EVP_PKEY_CTX_free(decrypt_ctx);
        if (read(client_socket, aes_iv, AES_BLOCK_SIZE) != AES_BLOCK_SIZE) {
            perror("Error receiving IV from client");
            exit(EXIT_FAILURE);
        }
        // Receiving encrypted message from client
        size_t ciphertext_len = read(client_socket, ciphertext, BUFFER_SIZE + AES_BLOCK_SIZE);
        if (ciphertext_len < 0)
        {
            perror("Error receiving ciphertext from client");
            exit(EXIT_FAILURE);
        }
        // Decrypting message using AES
        EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
        if (!aes_ctx || EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, decrypted_key, aes_iv) <= 0)
            handleErrors();
        int len;

        if (EVP_DecryptUpdate(aes_ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0)
            handleErrors();

        int plaintext_len = len;
        if (EVP_DecryptFinal_ex(aes_ctx, plaintext + len, &len) <= 0)
            handleErrors();
        plaintext_len += len;

        EVP_CIPHER_CTX_free(aes_ctx);

        // Output the decrypted message
        printf("Decrypted message from client: %.*s\n", plaintext_len, plaintext);

        // Close client socket
        close(client_socket);
    }

    // Freeing memory
    EVP_PKEY_free(rsa_key);
    close(server_socket);

    return 0;
}

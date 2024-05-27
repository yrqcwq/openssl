#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include<fcntl.h>
#include <openssl/core_names.h>

#define BUFFER_SIZE 1024
#define RSA_KEY_LENGTH 2048
#define AES_KEY_LENGTH 256
#define AES_BLOCK_SIZE 16
void handleErrors(void)
{
    fprintf(stderr, "Error occurred\n");
    exit(EXIT_FAILURE);
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

void send_aes_iv(char * data){
     // 打开要写入的文件
    FILE *file = fopen("aes_iv.txt", "w+");
    if (!file) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }

    // 写入数据到文件
    fwrite(data,1,AES_BLOCK_SIZE,file);

    // 关闭文件
    fclose(file);


}

int main()
{
    int client_socket;
    struct sockaddr_in server_addr;
    unsigned char plaintext[BUFFER_SIZE] ;
    unsigned char ciphertext[BUFFER_SIZE + AES_BLOCK_SIZE];
    unsigned char aes_key[AES_KEY_LENGTH / 8];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    EVP_PKEY *server_key = NULL;

    // Initializing OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);

    // Creating socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    // Server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(12349);

    // Connecting to server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error connecting to server");
        exit(EXIT_FAILURE);
    }

    // Receiving server's public key
    char public_key_pem[BUFFER_SIZE];
    size_t public_key_len = read(client_socket, public_key_pem, BUFFER_SIZE);
    if (public_key_len < 0)
    {
        perror("Error receiving public key from server");
        exit(EXIT_FAILURE);
    }

    BIO *bio = BIO_new_mem_buf(public_key_pem, public_key_len);
    PEM_read_bio_PUBKEY(bio, &server_key, NULL, NULL);
    BIO_free(bio);

    if (!server_key)
        handleErrors();

    // Generate AES key and IV
    generate_aes_key(aes_key, aes_iv);

    // Encrypt AES key using RSA
    unsigned char encrypted_key[BUFFER_SIZE];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0)
        handleErrors();

    size_t encrypted_key_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_key_len, aes_key, AES_KEY_LENGTH / 8) <= 0)
        handleErrors();
    if (EVP_PKEY_encrypt(ctx, encrypted_key, &encrypted_key_len, aes_key, AES_KEY_LENGTH / 8) <= 0)
        handleErrors();
    EVP_PKEY_CTX_free(ctx);
 
    // Send encrypted AES key to server
    if (write(client_socket, encrypted_key, encrypted_key_len) < 0)
    {
        perror("Error sending encrypted key to server");
        exit(EXIT_FAILURE);
    }
    //Sen AES IV
    send_aes_iv(aes_iv);
    // Encrypt message using AES
    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx || EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv) <= 0)
        handleErrors();

    
    printf("Enter message to send to server: ");
    fgets(plaintext, BUFFER_SIZE, stdin);
    int plaintext_len = strlen(plaintext);

    int len;
    if (EVP_EncryptUpdate(aes_ctx, ciphertext, &len, plaintext, plaintext_len) <= 0)
        handleErrors();
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(aes_ctx, ciphertext + len, &len) <= 0)
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(aes_ctx);
  
    // Send encrypted message to server
    if (write(client_socket, ciphertext, ciphertext_len) < 0)
    {
        perror("Error sending ciphertext to server");
        exit(EXIT_FAILURE);
    }

    // Close connection
    close(client_socket);
    EVP_PKEY_free(server_key);

    return 0;
}

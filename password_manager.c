#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX 100
#define TABLE_SIZE 1000
#define BLOCK_SIZE 16
#define SALT_SIZE 16

typedef struct {
    char website[MAX];
    char username[MAX];
    char password[MAX];
} Entry;

typedef struct {
    Entry entries[TABLE_SIZE];
    int count;
} HashTable;

void deriveKeyFromPassword(const unsigned char *password, const unsigned char *salt, unsigned char *key) {
    const int iterations = 10000; // Recommended: At least 10000 iterations
    const int key_length = 16; // For AES-128-CBC

    if (!PKCS5_PBKDF2_HMAC((const char *)password, -1, salt, SALT_SIZE, iterations, EVP_sha256(), key_length, key)) {
        fprintf(stderr, "Error deriving key from password.\n");
        exit(1);
    }
}

void encrypt(unsigned char *input, unsigned char *output, unsigned char *password, int length, unsigned char *iv, int *ciphertext_len, unsigned char *salt) {
    unsigned char key[16]; // For AES-128-CBC

    RAND_bytes(salt, SALT_SIZE); // Generate a random salt
    deriveKeyFromPassword(password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    int len;
    EVP_EncryptUpdate(ctx, output, &len, input, length);
    *ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, output + len, &len);
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(unsigned char *input, unsigned char *output, unsigned char *password, int length, unsigned char *iv, unsigned char *salt) {
    unsigned char key[16]; // For AES-128-CBC

    deriveKeyFromPassword(password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    int len;
    EVP_DecryptUpdate(ctx, output, &len, input, length);
    int plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, output + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    output[plaintext_len] = '\0'; // Ensure null termination
}

HashTable* createHashTable() {
    HashTable* hashTable = (HashTable*) malloc(sizeof(HashTable));
    hashTable->count = 0;
    return hashTable;
}

int hash(char *str) {
    int sum = 0;
    for (int i = 0; str[i]; i++) {
        sum += str[i];
    }
    return sum % TABLE_SIZE;
}

void addEntry(HashTable* hashTable, char *vault, char *master, char *website, char *username, char *password) {
    int index = hash(website);
    strcpy(hashTable->entries[index].website, website);
    strcpy(hashTable->entries[index].username, username);
    strcpy(hashTable->entries[index].password, password);
    hashTable->count++;

    unsigned char encrypted[MAX + BLOCK_SIZE]; // Adjust size for IV
    unsigned char data[MAX] = "";
    strcat((char *)data, website);
    strcat((char *)data, " ");
    strcat((char *)data, username);
    strcat((char *)data, " ");
    strcat((char *)data, password);

    unsigned char iv[BLOCK_SIZE], salt[SALT_SIZE];
    RAND_bytes(iv, BLOCK_SIZE);

    int ciphertext_len;
    encrypt(data, encrypted, (unsigned char *)master, strlen((char *)data), iv, &ciphertext_len, salt);

    FILE *file = fopen(vault, "ab");
    if (file == NULL) {
        printf("Could not open file %s\n", vault);
        return;
    }

    // Write salt, IV, and encrypted data to file
    fwrite(salt, sizeof(unsigned char), SALT_SIZE, file); // Write salt to file
    fwrite(iv, sizeof(unsigned char), BLOCK_SIZE, file); // Write IV to file
    fwrite(&ciphertext_len, sizeof(int), 1, file); // Write the length of encrypted data
fwrite(encrypted, sizeof(char), ciphertext_len, file); // Write the encrypted data
fclose(file);
}

void getEntry(char *vault, char *master, char *website) {
    FILE *file = fopen(vault, "rb");
    if (file == NULL) {
        printf("Could not open file %s\n", vault);
        return;
    }

    while (!feof(file)) {
        unsigned char salt[SALT_SIZE], iv[BLOCK_SIZE];
        if (fread(salt, sizeof(unsigned char), SALT_SIZE, file) != SALT_SIZE) {
            break; // Handle error or end of file
        }
        if (fread(iv, sizeof(unsigned char), BLOCK_SIZE, file) != BLOCK_SIZE) {
            break; // Break if we cannot read an IV - likely end of file
        }

        int length;
        if (fread(&length, sizeof(int), 1, file) != 1) {
            break; // Handle error or end of file
        }
        unsigned char encrypted[MAX + BLOCK_SIZE];
        if (fread(encrypted, sizeof(char), length, file) != (size_t)length) {
            break; // Break if the encrypted data read does not match the expected length
        }

        unsigned char decrypted[MAX];
        decrypt(encrypted, decrypted, (unsigned char *)master, length, iv, salt);

        char *token = strtok((char *)decrypted, " ");
        if (token != NULL && strcmp(token, website) == 0) {
            printf("Website: %s\n", token);
            token = strtok(NULL, " ");
            printf("Username: %s\n", token);
            token = strtok(NULL, " ");
            printf("Password: %s\n", token);
            fclose(file);
            return;
        }
    }
    printf("Entry not found.\n");
    fclose(file);
}

int main() {
    HashTable* hashTable = createHashTable();
    char vault[MAX], master[MAX], website[MAX];

    printf("Enter vault file name: ");
    scanf("%s", vault);
    printf("Enter master password: ");
    scanf("%s", master);

    int choice;
    do {
        printf("Enter 1 to add entry, 2 to get entry, 3 to quit: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter website: ");
                scanf("%s", website);
                char username[MAX], password[MAX];
                printf("Enter username: ");
                scanf("%s", username);
                printf("Enter password: ");
                scanf("%s", password);
                addEntry(hashTable, vault, master, website, username, password);
                break;
            case 2:
                printf("Enter website: ");
                scanf("%s", website);
                getEntry(vault, master, website);
                break;
            case 3:
                printf("Quitting...\n");
                break;
            default:
                printf("Invalid choice.\n");
        }
    } while (choice != 3);

    free(hashTable);
    return 0;
}
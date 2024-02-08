#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define MAX 100
#define TABLE_SIZE 1000
#define BLOCK_SIZE 16

typedef struct {
    char website[MAX];
    char username[MAX];
    char password[MAX];
} Entry;

typedef struct {
    Entry entries[TABLE_SIZE];
    int count;
} HashTable;

// Function to encrypt the string using AES
void encrypt(char *input, char *output, char *key, int length) {
    AES_KEY encryptKey;
    AES_set_encrypt_key(key, 128, &encryptKey);
    unsigned char iv[BLOCK_SIZE];
    RAND_bytes(iv, BLOCK_SIZE);
    AES_cbc_encrypt(input, output, length, &encryptKey, iv, AES_ENCRYPT);
}

// Function to decrypt the string using AES
void decrypt(char *input, char *output, char *key, int length) {
    AES_KEY decryptKey;
    AES_set_decrypt_key(key, 128, &decryptKey);
    unsigned char iv[BLOCK_SIZE];
    RAND_bytes(iv, BLOCK_SIZE);
    AES_cbc_encrypt(input, output, length, &decryptKey, iv, AES_DECRYPT);
}

// Function to create a new hash table
HashTable* createHashTable() {
    HashTable* hashTable = (HashTable*) malloc(sizeof(HashTable));
    hashTable->count = 0;
    return hashTable;
}

// Simple hash function
int hash(char *str) {
    int sum = 0;
    for (int i = 0; i < strlen(str); i++) {
        sum += str[i];
    }
    return sum % TABLE_SIZE;
}

// Function to add an entry to the hash table and save it to the vault
void addEntry(HashTable* hashTable, char *vault, char *master, char *website, char *username, char *password) {
    int index = hash(website);
    strcpy(hashTable->entries[index].website, website);
    strcpy(hashTable->entries[index].username, username);
    strcpy(hashTable->entries[index].password, password);
    hashTable->count++;

    char encrypted[MAX];
    char data[MAX] = "";
    strcat(data, website);
    strcat(data, " ");
    strcat(data, username);
    strcat(data, " ");
    strcat(data, password);
    encrypt(data, encrypted, master, strlen(data));
    FILE *file = fopen(vault, "a");
    if (file == NULL) {
        printf("Could not open file %s", vault);
        return;
    }
    int length = strlen(encrypted);
    fwrite(&length, sizeof(int), 1, file);
    fwrite(encrypted, sizeof(char), length, file);
    fclose(file);
}

// Function to get an entry from the hash table
Entry* getEntry(HashTable* hashTable, char *website) {
    int index = hash(website);
    return &hashTable->entries[index];
}

int main() {
    HashTable* hashTable = createHashTable();
    char vault[MAX];
    char master[MAX];
    char website[MAX];
    char username[MAX];
    char password[MAX];

    printf("Enter vault file name: ");
    scanf("%s", vault);
    printf("Enter master password: ");
    scanf("%s", master);

    while (1) {
        printf("Enter 1 to add entry, 2 to get entry, 3 to quit: ");
        int choice;
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter website: ");
                scanf("%s", website);
                printf("Enter username: ");
                scanf("%s", username);
                printf("Enter password: ");
                scanf("%s", password);
                addEntry(hashTable, vault, master, website, username, password);
                break;
            case 2:
                printf("Enter website: ");
                scanf("%s", website);
                Entry* entry = getEntry(hashTable, website);
                FILE *file = fopen(vault, "r");
                if (file == NULL) {
                    printf("Could not open file %s", vault);
                    return 1;
                }
                while (!feof(file)) {
                    int length;
                    fread(&length, sizeof(int), 1, file);
                    char encrypted[MAX];
                    fread(encrypted, sizeof(char), length, file);
                    char decrypted[MAX];
                    decrypt(encrypted, decrypted, master, length);
                    decrypted[length] = '\0';  // Null-terminate the decrypted data
                    char *token = strtok(decrypted, " ");
                    if (strcmp(token, website) == 0) {
                        printf("Website: %s\n", token);
                        token = strtok(NULL, " ");
                        printf("Username: %s\n", token);
                        token = strtok(NULL, " ");
                        printf("Password: %s\n", token);
                        break;
                    }
                }
                fclose(file);
                break;
            case 3:
                return 0;
            default:
                printf("Invalid choice\n");
        }
    }
}
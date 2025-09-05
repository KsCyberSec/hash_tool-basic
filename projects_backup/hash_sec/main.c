#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void menu()
{
    printf("\n ---------------------------------\n");
    printf("            Hash Menu           ");
    printf("\n ---------------------------------\n");
    printf("1. hash generate\n");
    printf("2. hash cracker\n");
    printf("3. discover hash\n");
    printf("4. exit\n");
}

void hash_type_selection(const char* input)
{
// context for hash
    char hash_type[20];
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash_value[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

// prompt user to select hash
    printf("Select hash type (md5, sha256, sha512, ripemd160): ");
    scanf("%s", hash_type);

// get hash algoritmhm by name
    md = EVP_get_digestbyname(hash_type);
    if (!md)
    {
        printf("hash type not found\n");
        return;
    }

// create and initialize the context);
    mdctx = EVP_MD_CTX_new();
    if(!mdctx)
    {
        printf("Error creating digest context.\n");
        return;
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
    {
        printf("Error intializing digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

// digest update
    if (1 != EVP_DigestUpdate(mdctx, input, strlen(input)))
    {
        printf("Error updating digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

// finalize the digest
    if (1 != EVP_DigestFinal_ex(mdctx, hash_value, &hash_len))
    {
        printf("Error finalizing digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

// print the hash value
    printf("Input: %s\n", input);
    printf("Hash (%s): ", hash_type);
    for (unsigned int i = 0; i < hash_len; i++)
    {
        printf("%02x", hash_value[i]);
    }
    printf("\n");

// free the context
    EVP_MD_CTX_free(mdctx);
}

void discover_hash_type(){
    char discover_hash[256];
    printf("Enter the hash value: ");
    scanf("%s", discover_hash);

    // finding out by size
    size_t length_hash = strlen(discover_hash);
    if (length_hash == 32){
        printf("Hash type: MD5");
        return;
    } else if (length_hash == 64){
        printf("Hash type: SHA256");
        return;
    } else if (length_hash == 128){
        printf("Hash type: SHA512");
        return;
    } else if (length_hash == 40){
        printf("Hash type: RIPEMD160");
        return;
    }

    // finding out by prefix
    if (strncmp(discover_hash, "$2a$", 4) == 0 || strncmp(discover_hash, "$2b$", 4) == 0 || strncmp(discover_hash, "$2y$", 4) == 0){
        printf("Hash type: bcrypt\n");
        return;
    }
    if (strncmp(discover_hash, "$argon2", 7) == 0){
        printf("Hash type: Argon2\n");
        return;
    }
    if (strncmp(discover_hash, "$6$", 3) == 0){
        printf("Hash type: SHA512-Crypt (linux)\n");
        return;
    }
    if (strncmp(discover_hash, "$1$", 3) == 0){
        printf("Hash type: MD5-Crypt (linux)\n");
        return;
    }
}
void hash_cracker(const char* input_cracker){

}

int main()
{
    int choice;
    char input[256];
    char input_cracker[256];

    do
    {
        menu();
        scanf("%d", &choice);

        switch(choice)
        {
        case 1:
            printf("Enter input string to hash: ");
            scanf("%s", input);
            hash_type_selection(input);
            break;

        case 2:
            printf("Enter the hash: ");
            scanf("%s", input_cracker);
            break;

        case 3:
            discover_hash_type();
            break;

        case 4:
            printf("BYEEE");
            break;

        default:
            printf("Invalid input");
        }
    } while (choice != 4);
    return 0;
}

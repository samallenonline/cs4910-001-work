/*
CS4910-001 Intro to Computer Security
Lab #1 Task 7
Sam Allen

Objective: Given a plaintext and ciphertext, find
the key that is used for the encryption using brute
force techniques.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>

#define DICT_PATH "rockyou.txt"
#define LINE_BUFFER 256
#define KEY_LENGTH 16  // 16 bytes, 128 bit key

/*
Information given in assignment instructions (ciphertext and initial vector are 
defined as bytes to avoid having to parse and convert).
*/
#define KNOWN_PLAINTEXT "This is a top secret."
static const int CIPHERTEXT_LEN = 32;
static const unsigned char CIPHERTEXT[32] = {
    0x76,0x4a,0xa2,0x6b,0x55,0xa4,0xda,0x65,
    0x4d,0xf6,0xb1,0x9e,0x4b,0xce,0x00,0xf4,
    0xed,0x05,0xe0,0x93,0x46,0xfb,0x0e,0x76,
    0x25,0x83,0xcb,0x7d,0xa2,0xac,0x93,0xa2
};
static const unsigned char IV[16] = {
    0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x99,
    0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11
};

/*
This function strips a string by removing whitespace, newline
characters, and other formatting characters.
*/
void strip(char *s) 
{
    int length = strlen(s);
    while (length > 0)  // iterate through every character in string
    {
        char c = s[length - 1];
        if (isspace((unsigned char)c)) // if character is a formatting character,
        {
            s[--length] = '\0'; // make null
        } else 
        {
            break;  // a non-formatting character, stop iteration
        }
    }
}

/*
This function pads a string with hash symbols '#' to ensure 
that it reaches the key length.
*/
char *pad_string(char *word) {
    int word_length = strlen(word); // get length of word

    // declare variable for padded string and allocate memory
    char *padded = (char *)malloc(16+1);
    if(!padded) return NULL;

    // create padded string using given word
    memset(padded, '#', 16);
    memcpy(padded, word, word_length);
    padded[16] = '\0';  // string terminator
    return padded;
}

/*
Decrypt the ciphertext using a given key and compare the result 
with the known plaintext. Return 1 if the plaintext are equivalent, 
and return 0 otherwise.
 */
static int decrypt_and_compare(const unsigned char key[KEY_LENGTH]) {
    int key_found = 0; // 1 = key found, 0 = key not found

    // create EVP cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    // allocate buffer 
    unsigned char *pt = (unsigned char*)malloc(CIPHERTEXT_LEN + EVP_MAX_BLOCK_LENGTH);
    if (!pt) 
    { 
        // if allocation failed, free up memory and exit
        EVP_CIPHER_CTX_free(ctx); 
        return 0; 
    }

    // declare variables to hold bytes written by decrypt functions
    int outl1 = 0;
    int outl2 = 0;

    // initialize and perform decryption operation using AES_128_CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV) != 1) goto cleanup;
    if (EVP_DecryptUpdate(ctx, pt, &outl1, CIPHERTEXT, CIPHERTEXT_LEN) != 1) goto cleanup;
    if (EVP_DecryptFinal_ex(ctx, pt + outl1, &outl2) != 1) goto cleanup;

    {
        // obtain plaintext
        int plaintext_len = outl1 + outl2;
        const size_t ref_len = strlen(KNOWN_PLAINTEXT);

        // check that known plaintext and obtained plaintext are exactly equivalent
        if (plaintext_len == (int)ref_len && memcmp(pt, KNOWN_PLAINTEXT, ref_len) == 0) {
            // if yes, key is found
            key_found = 1;
        }
    }

cleanup:
    // free up memory and exit
    free(pt);
    EVP_CIPHER_CTX_free(ctx);
    return key_found;
}

/* 
This function converts a string to hex and prints the output
for debugging purposes
*/
static void print_hex(const unsigned char *buf, size_t len) 
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
}

int main(void) {
    // open text file with reading mode
    FILE *fptr = fopen(DICT_PATH, "r");
    if (!fptr) {
        perror("\n> Failed to open dictionary file");
        return 1;
    }

    // initialize variables
    char line[LINE_BUFFER];
    unsigned char key[KEY_LENGTH];
    size_t tested = 0;

    // start reading each line in the text file
    while (fgets(line, sizeof(line), fptr)) {

        strip(line);    // strip line of formatting characters
        if (strlen(line) < KEY_LENGTH)  // ensure word is less than 16 characters
        {
            char *padded = pad_string(line);
            if (padded)
            {
                printf("\nKey guess: %s", line);
                printf("\nPadded: %s", padded); 

                memcpy(key, padded, 16);

                printf("\nHex value: "); print_hex(key, KEY_LENGTH);
                printf("\n");

                if (decrypt_and_compare(key)) {
                    printf("\n> Correct key word: \"%s\"", line);
                    printf("\n> 16-byte AES key: ");
                    print_hex(key, KEY_LENGTH);
                    printf("\n");

                    // clean-up
                    free(padded);
                    fclose(fptr);
                    return 0;
                }
                free(padded);
            }
        }
    }
    // clean-up and exit
    fclose(fptr);
    printf("\n> No matching key found in dictionary.\n");
    return 1;
}
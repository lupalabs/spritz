#include "spritz.h"
#include <stdio.h>
#include <string.h>

void TestHelloWorld(void) {
    byte* message = "Hello World!";
    byte* key = "secret";
    size_t len = strlen(message);

    byte* ciphertext = Encrypt(key, strlen(key), message, len);

    printf("Encrypted message: %.*s \n", len, ciphertext);

    byte* decrypted = Decrypt(key, strlen(key), ciphertext, len);

    printf("Decrpyted message: %.*s \n", len, decrypted);
}

void TestSuperLongMessage(void) {
    byte* message = "This is a super long message that contains more than N characters. Does this destroy everything. Or is this just stupid? How long can the text be? It remains a mystery! Wow that rimes. So funny! Greetings Luca.";
    byte* key = "supersecretkey";
    size_t len = strlen(message);

    byte* ciphertext = Encrypt(key, strlen(key), message, len);

    printf("Encrypted message: %.*s \n", len, ciphertext);

    byte* decrypted = Decrypt(key, strlen(key), ciphertext, len);

    printf("Decrpyted message: %.*s \n", len, decrypted);
}

int main(void) {

    TestHelloWorld();    
    TestSuperLongMessage();

    return 0;
}
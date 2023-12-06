#include "../util/util.h"
#include <stdlib.h>

#define N 256
#define D N/8
#define HIGH(b) b%D
#define LOW(b) b/D

/**
 * From "Spritz—a spongy RC4-like stream cipher and hash function"
 * Ronald L. Rivest and Jacob C. N. Schmidt
 * November 10. 2014 (rev. August 31. 2016)
 * 
 * C implementation of the Pseudocode provided in the paper was written by Jan Luca Pawlik
 * 
*/

typedef struct State_t {
    u64 i;
    u64 j;
    u64 k;
    u64 z;
    u64 a;
    u64 w;
    byte* State;
} State;

static State g_state = {0};

static void InitializeState(u64 n) {

    g_state.i = g_state.j = g_state.k = g_state.z = g_state.a = 0;
    g_state.w = 1;
    g_state.State = (byte*)malloc(n * sizeof(byte));

    for (u64 v = 0; v < N; v++) {
        g_state.State[v] = v;
    }
}

static u64 GCD(u64 a, u64 b) {
    u64 temp;

    while (b != 0) {
        temp = a % b;
        a = b;
        b = temp;
    }

    return a;

}

static u64 Output(void) {

    byte* S = g_state.State;

    g_state.z = S[(g_state.j + S[(g_state.i + S[(g_state.z + g_state.k) % N]) % N ]) % N];
    return g_state.z;
}

static void Swap(byte* a, byte* b){
    byte tmp = *a;
    *a = *b;
    *b = tmp;
}

static void Update(void) {
    
    byte* S = g_state.State;

    g_state.i = (g_state.i + g_state.w) % N;
    g_state.j = (g_state.k + S[(g_state.j + S[g_state.i]) % N]) % N;
    g_state.k = (g_state.i + g_state.k + S[g_state.j]) % N;
    Swap(&S[g_state.i], &S[g_state.j]);
}

static void Crush(void) {

    byte* S = g_state.State;

    for (u64 v = 0; v < N / 2; v++) {
        if (S[v] > S[N - 1 - v]){
            Swap(&S[v], &S[N - 1 - v]);
        } 
    }
}

static void Whip(u64 r) {
    for (u64 v = 0; v < r; v++){
        Update();
    }
    do {
        g_state.w += 1;
    } while (GCD(g_state.w, N) != 1);
}

static void Shuffle(void) {
    Whip(2 * N);
    Crush();
    Whip(2 * N);
    Crush();
    Whip(2 * N);
    g_state.a = 0;
}

static u64 Drip(void) {
    if (g_state.a > 0) {
        Shuffle();
    }
    Update();
    return Output();
}

static byte* Squeeze(u64 r) {
    if (g_state.a > 0) {
        Shuffle();
    }

    byte* P = (byte*)malloc(r * sizeof(byte));

    for (u64 v = 0; v < r; v++){
        P[v] = Drip();
    }

    return P;
}

static void AbsorbByte(byte* Input) {

    byte* S = g_state.State;
    // AbsorbNibble(low)
    if (g_state.a == N / 2) {
        Shuffle();
    }
    Swap(&S[g_state.a], &S[((N / 2) + LOW(*Input)) % N]);
    g_state.a += 1;
    // AbsorbNibble(high)
    if (g_state.a == N / 2) {
        Shuffle();
    }
    Swap(&S[g_state.a], &S[((N / 2) + HIGH(*Input)) % N]);
    g_state.a += 1;

}

static void Absorb(byte* Input, u64 InputLength) {
    for (u64 v = 0; v < InputLength; v++) {
        AbsorbByte(&Input[v]);
    } 
}

static void AbsorbStop(void) {
    if (g_state.a == N / 2) {
        Shuffle();
    }
    g_state.a += 1;
}

static void KeySetup(byte* key, usize keylength) {
    InitializeState(N);
    Absorb(key, keylength);
}

// Public Functions

byte* Encrypt(byte* key, usize keylength, byte* message, usize messageLength){
    KeySetup(key, keylength);
    byte* Ciphertext = (byte*)malloc(messageLength * sizeof(byte));
    byte* squeeze = Squeeze(messageLength);

    for (usize i = 0; i < messageLength; i++){
        Ciphertext[i] = (message[i] + squeeze[i]) % 256;
    }

    return Ciphertext;
}


byte* Decrypt(byte* key, usize keylength, byte* cipherText, usize cipherTextLength){
    KeySetup(key, keylength);
    byte* Cleartext = (byte*)malloc(cipherTextLength * sizeof(byte));
    byte* squeeze = Squeeze(cipherTextLength);

    for (usize i = 0; i < cipherTextLength; i++){
        Cleartext[i] = (cipherText[i] - squeeze[i]) % 256;
    }

    return Cleartext;
}

byte* SPRITZ_EncryptIV(byte* key, usize keylength, byte* iv, usize ivLength, byte* message, usize messageLength){
    KeySetup(key, keylength);
    AbsorbStop();
    Absorb(iv, ivLength);
    byte* Ciphertext = (byte*)malloc(messageLength * sizeof(byte));
    byte* squeeze = Squeeze(messageLength);

    for (usize i = 0; i < messageLength; i++){
        Ciphertext[i] = (message[i] + squeeze[i]) % 256;
    }

    return Ciphertext;
}

byte* SPRITZ_DecryptIV(byte* key, usize keylength, byte* iv, usize ivLength, byte* cipherText, usize cipherTextLength){
    KeySetup(key, keylength);
    AbsorbStop();
    Absorb(iv, ivLength);
    byte* Cleartext = (byte*)malloc(cipherTextLength * sizeof(byte));
    byte* squeeze = Squeeze(cipherTextLength);

    for (usize i = 0; i < cipherTextLength; i++){
        Cleartext[i] = (cipherText[i] + squeeze[i]) % 256;
    }

    return Cleartext;
}

byte* Hash(byte* mesage, usize messageLength, usize hashlength){
    InitializeState(N);
    Absorb(mesage, messageLength);
    AbsorbStop();
    Absorb(&hashlength, sizeof(hashlength));
    return Squeeze(hashlength);
}

byte* SPRITZ_DomHash(byte* domainName, usize domainNameLength, byte* message, usize messageLength, usize hashlength){
    InitializeState(N);
    Absorb(domainName, domainNameLength);
    AbsorbStop();
    Absorb(message, messageLength);
    AbsorbStop();
    Absorb(&hashlength, sizeof(hashlength));
    return Squeeze(hashlength);
}

byte* SPRITZ_Mac(byte* key, usize keylength, byte* message, usize messageLength, usize maclength){
    InitializeState(N);
    Absorb(key, keylength);
    AbsorbStop();
    Absorb(message, messageLength);
    AbsorbStop();
    Absorb(&maclength, sizeof(maclength));
    return Squeeze(maclength);
}
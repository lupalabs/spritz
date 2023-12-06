#ifndef _SPRITZ_H
#define _SPRIZ_H

#include "../util/util.h"

byte* SPRITZ_Encrypt(byte* key, usize keylength, byte* message, usize messageLength);
byte* SPRITZ_Decrypt(byte* key, usize keylength, byte* cipherText, usize cipherTextLength);

byte* SPRITZ_EncryptIV(byte* key, usize keylength, byte* iv, usize ivLength, byte* message, usize messageLength);
byte* SPRITZ_DecryptIV(byte* key, usize keylength, byte* iv, usize ivLength, byte* cipherText, usize cipherTextLength);

// byte* SPRITZ_EncryptAEAD(byte* key, usize keylength, u64 nonce, byte* header, usize headerLength, byte* message, usize messageLength, usize tagLength);
// byte* SPRITZ_DecryptAEAD(byte* key, usize keylength, u64 nonce, byte* header, usize headerLength, byte* message, usize messageLength, usize tagLength);

byte* SPRITZ_Hash(byte* mesage, usize messageLength, usize hashlength);
byte* SPRITZ_DomHash(byte* domainName, usize domainNameLength, byte* message, usize messageLength, usize hashlength);

byte* SPRITZ_Mac(byte* key, usize keylength, byte* message, usize messageLength, usize maclength);

#endif
#include "sha1.h"
#include "translator.h"
#ifndef MYSHA_H_
#define MYSHA_H_


class HashSHA{
private:
unsigned    message_digest[5];          // Message digest from "sha"
FILE *fp;

SHA1 sha;
translator trl;
string hexstring;
public :

HashSHA();
void hashFoo(bitstring b);
bitstring getDigest();
};

#endif

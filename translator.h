#ifndef TRANSLATOR_H_
#define TRANSLATOR_H_
 
#include "bitstring.h"

#define MAX 64 
#define MAX4 128
using namespace std;

class translator {
private: 
int arraytemp[4];
//#TODO normalizar os valores, apenas length de 4 bits, e numeros de 0-F, 
//#TODO criar uma funçao que mede (ex:512bits de input)	e verifica que não vai dar != de multiplo de 4
string hexa;
bitstring bites;
public:
//int b[4];
string chares;
//int bang[4];


translator(bitstring a_);
//translator(int  *a_);
translator(string b);
translator();
~translator();

int  chartoBits(char izard);
char array2Hex(int *a);
void bitstr2Char(bitstring b);
bitstring toBstr(string arr);
void valuetosha();
string getHexstring();
bitstring getBitstring();

};

#endif


#ifndef Composition_H_
#define Composition_H_

#define UNDEFINED 1
#define BEINGDEFINED 2
#define DEFINED 3
/*#define SIZE 160 //b-bit size
#define BSIZE 128 // the actual b-size;
//#define ASIZE 512 // a-bit size
#define msize 512 // m-bit size
//#define LSIZE 512 
#define TSIZE 9 // 2^9 = 512 = L
//#define SIZE 128
//#define ASIZE 768
//#define msize 512
*/

#include <iomanip>

#include <iostream>
#include <sstream>
#include <cmath>
#include "bitstring.h"
#include <vector>
using namespace std;

//NTL_CLIENT

class Composition {
private: 

	
public:
	/* Valores de itaka */
	int n;
	//int d;
	int len;
	/* Valores de itaka */
	
	/* Valores da Composition */
	int outsize;
	int bsize;
	int asize;
	int tsize;
	/* Valores da Composition */

	bool isHashed;
	int l;
	int delta;
	int j;
	int i_linha,j_linha;
	vector <int> status;
	/*
	bitstring S[msize]; // contains b-bit arrays 
	bitstring h[msize]; // contains b-bit arrays
	bitstring hcopy[msize]; // contains b-bit arrays
	bitstring x[msize]; // contains m-bit arrays
	bitstring Msk[msize]; // contains m-bit arrays
	bitstring S_0;
	bitstring key;
	*/
	vector <bitstring> S; // contains b-bit arrays 
	vector <bitstring> copyS; // contains b-bit arrays 
	vector <bitstring> h;	
	//bitstring h; // contains b-bit arrays
	vector <bitstring> hcopy; // contains b-bit arrays
	vector <bitstring> x; // contains m-bit arrays
	vector <bitstring> Msk; // contains m-bit arrays
	bitstring S_0;
	bitstring key; //maybe the same as x
	//bitstring x;	
	//bitstring w;

	Composition();
	virtual ~Composition();
	//Composition(int n,int d, int l, bitstring w, bitstring x_, int delta);
	Composition( int outputlength, bitstring w_, bitstring x_,int delta_);
	Composition( int outputlength, bitstring w_, bitstring x_,vector <bitstring> rs,vector <bitstring> aMsk,int delta_);

	//Composition(int n,int d, int l, bitstring w, bitstring x_,vector <bitstring> rs,int delta);
	//Composition(bitstring w,bitstring k); //mudar a assinatura para o tipo certo

	//Composition(bitstring[] x,int delta,bitstring K,bitstring S,int t); //mudar a assinatura para o tipo certo
	//virtual ~Composition();

	bitstring creat_Digest();
	bitstring hashBitstring(bitstring a);
	int vTwo(int i);
	void creat_Composition();
	void creat_Composition(vector <bitstring> rs,vector <bitstring> aMsk);
	bitstring concat(bitstring a,bitstring b);
	bitstring getRes();
	//bitstring hashBitstring(bitstring b);
	void copyH();
//	void resetH();
	void init(bitstring x,bitstring y);
	void toString();
	bitstring extract();	
	vector<bitstring> getS();	
	//unsigned char *fooHex(unsigned char *dst, const unsigned char *src);
	//int main();
	
};

#endif

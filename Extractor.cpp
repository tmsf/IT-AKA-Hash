/*
 * Extractor.cpp
 *
 *  Created on: 7/Set/2009
 *      Author: Helder
 */

#include <stdexcept>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/ZZ_pE.h>
#include <NTL/ZZ_pEX.h>
#include <iostream>
#include <sstream>

#include "Extractor.h"

NTL_CLIENT

Extractor::Extractor() {
}

Extractor::Extractor(int _n, int _k, int _d, int _l, float _epsilon) {
	n = _n;
	k = _k;
	d = _d;
	l = _l;
	epsilon = _epsilon;


	// Polinomio irredutivel 2^32 (x^32 + x^15 + x^9 +x^7 + x^4 + x^3 + 1) ???
	ZZ p;
	p=2;
	ZZ_p::init(p);
	ZZ_p one;
	one=1;
	ZZ_pX a1(0,one),a2(3,one),a3(4,one), a4(7,one), a5(9,one), a6(15,one), a7(32,one);
	ZZ_pX mod32;
	mod32 = a1 + a2 + a3 + a4 + a5 + a6 + a7;

	ZZ_pE::init(mod32);


	// Polinomio irredutivel 2^32^32

	string c[32];
	ZZ_pE wp[32];

	// (X^30 + X^28 + X^27 + X^26 + X^21 + X^20 + X^19 + X^18 + X^15 + X^14 + X^11 + X^4 + X^3 + X^2 + X) +
	c[0] 	= "[0 1 0 1 1 1 0 0 0 0 1 1 1 1 0 0 1 1 0 0 1 0 0 0 0 0 0 1 1 1 1 0]";
	// (X^30 + X^27 + X^26 + X^24 + X^22 + X^21 + X^20 + X^18 + X^17 + X^16 + X^13 + X^12 + X^11 + X^10 + X^7 + X^6 + X^3 + X^2)*Y +
	c[1] 	= "[0 1 0 0 1 1 0 1 0 1 1 1 0 1 1 1 0 0 1 1 1 1 0 0 1 1 0 0 1 1 0 0]";
	// (X^31 + X^30 + X^29 + X^28 + X^27 + X^25 + X^22 + X^18 + X^16 + X^14 + X^13 + X^11 + X^9 + X^7 + X^3 + X^2 + X + 1)*Y^2 +
	c[2] 	= "[1 1 1 1 1 0 1 0 0 1 0 0 0 1 0 1 0 1 1 0 1 0 1 0 1 0 0 0 1 1 1 1]";
	// (X^31 + X^28 + X^22 + X^21 + X^19 + X^18 + X^15 + X^13 + X^10 + X^9 + X^8 + X^7 + X^5 + X^4 + X^2 + 1)*Y^3 +
	c[3] 	= "[1 0 0 1 0 0 0 0 0 1 1 0 1 1 0 0 1 0 1 0 0 1 1 1 1 0 1 1 0 1 0 1]";
	// (X^31 + X^30 + X^27 + X^26 + X^25 + X^24 + X^23 + X^21 + X^16 + X^12 + X^9 + X^8 + X^6 + X^3 + X^2)*Y^4 +
	c[4] 	= "[1 1 0 0 1 1 1 1 1 0 1 0 0 0 0 1 0 0 0 1 0 0 1 1 0 1 0 0 1 1 0 0]";
	// (X^31 + X^30 + X^29 + X^28 + X^27 + X^26 + X^24 + X^23 + X^22 + X^21 + X^20 + X^18 + X^15 + X^12 + X^9 + X^7 + X^6 + X^5 + X^4 + X^3)*Y^5 +
	c[5] 	= "[1 1 1 1 1 1 0 1 1 1 1 1 0 1 0 0 1 0 0 1 0 0 1 0 1 1 1 1 1 0 0 0]";
	// (X^31 + X^29 + X^25 + X^21 + X^20 + X^19 + X^17 + X^16 + X^14 + X^13 + X^11 + X^10 + X^9 + X^5 + X^4 + X^3 + X + 1)*Y^6 +
	c[6] 	= "[1 0 1 0 0 0 1 0 0 0 1 1 1 0 1 1 0 1 1 0 1 1 1 0 0 0 1 1 1 0 1 1]";
	// (X^31 + X^30 + X^29 + X^28 + X^24 + X^22 + X^19 + X^17 + X^16 + X^10 + X^8 + X^7 + X^6 + X^5 + X^3 + X^2)*Y^7 +
	c[7] 	= "[1 1 1 1 0 0 0 1 0 1 0 0 1 0 1 1 0 0 0 0 0 1 0 1 1 1 1 0 1 1 0 0]";
	// (X^31 + X^30 + X^29 + X^25 + X^21 + X^20 + X^18 + X^16 + X^14 + X^13 + X^12 + X^10 + X^9 + X^8 + X^7 + X^6 + X^3)*Y^8 +
	c[8] 	= "[1 1 1 0 0 0 1 0 0 0 1 1 0 1 0 1 0 1 1 1 0 1 1 1 1 0 0 0 1 0 0 0]";
	// (X^27 + X^26 + X^23 + X^18 + X^17 + X^16 + X^14 + X^13 + X^12 + X^10 + X^8 + X^7 + X^4 + X^3 + X^2)*Y^9 +
	c[9] 	= "[0 0 0 0 1 1 0 0 1 0 0 0 0 1 1 1 0 1 1 1 0 1 0 1 1 0 0 1 1 1 0 0]";
	// (X^28 + X^25 + X^24 + X^23 + X^20 + X^19 + X^18 + X^17 + X^16 + X^14 + X^13 + X^12 + X^11 + X^10 + X^7 + X^4 + X^3 + X)*Y^10 +
	c[10] 	= "[0 0 0 1 0 0 1 1 1 0 0 1 1 1 1 1 0 1 1 1 1 1 0 0 1 0 0 1 1 0 1 0]";
	// (X^31 + X^29 + X^28 + X^27 + X^23 + X^22 + X^17 + X^16 + X^10 + X^9 + X^7 + X^5 + X^4 + X^3 + X^2)*Y^11 +
	c[11] 	= "[1 0 1 1 1 0 0 0 1 1 0 0 0 0 1 1 0 0 0 0 0 1 1 0 1 0 1 1 1 1 0 0]";
	// (X^30 + X^29 + X^23 + X^22 + X^21 + X^20 + X^18 + X^16 + X^14 + X^13 + X^12 + X^10 + X^9 + X^4)*Y^12 +
	c[12] 	= "[0 1 1 0 0 0 0 0 1 1 1 1 0 1 0 1 0 1 1 1 0 1 1 0 0 0 0 1 0 0 0 0]";
	// (X^29 + X^25 + X^22 + X^20 + X^17 + X^16 + X^15 + X^13 + X^9 + X^8 + X^7 + X^6 + X^5 + X^4 + X^2)*Y^13 +
	c[13] 	= "[0 0 1 0 0 0 1 0 0 1 0 1 0 0 1 1 1 0 1 0 0 0 1 1 1 1 1 1 0 1 0 0]";
	// (X^31 + X^29 + X^27 + X^26 + X^17 + X^16 + X^14 + X^13 + X^10 + X^7 + X^4 + X^3)*Y^14 +
	c[14] 	= "[1 0 1 0 1 1 0 0 0 0 0 0 0 0 1 1 0 1 1 0 0 1 0 0 1 0 0 1 1 0 0 0]";
	// (X^31 + X^30 + X^26 + X^25 + X^24 + X^19 + X^17 + X^16 + X^15 + X^13 + X^12 + X^9 + X^8 + X^7 + X^6 + X^4 + X + 1)*Y^15 +
	c[15] 	= "[1 1 0 0 0 1 1 1 0 0 0 0 1 0 1 1 1 0 1 1 0 0 1 1 1 1 0 1 0 0 1 1]";
	// (X^31 + X^30 + X^27 + X^26 + X^25 + X^24 + X^23 + X^20 + X^19 + X^18 + X^14 + X^12 + X^11 + X^9 + X^8 + X^6 + X^5 + X^3 + X^2)*Y^16 +
	c[16] 	= "[1 1 0 0 1 1 1 1 1 0 0 1 1 1 0 0 0 1 0 1 1 0 1 1 0 1 1 0 1 1 0 0]";
	// (X^31 + X^30 + X^29 + X^28 + X^25 + X^21 + X^20 + X^19 + X^18 + X^17 + X^15 + X^13 + X^12 + X^11 + X^9 + X^8 + X^7 + X^2)*Y^17 +
	c[17] 	= "[1 1 1 1 0 0 1 0 0 0 1 1 1 1 1 0 1 0 1 1 1 0 1 1 1 0 0 0 0 1 0 0]";
	// (X^31 + X^30 + X^24 + X^23 + X^19 + X^17 + X^15 + X^10 + X^8 + X^6 + X^3 + X^2)*Y^18 +
	c[18] 	= "[1 1 0 0 0 0 0 1 1 0 0 0 1 0 1 0 1 0 0 0 0 1 0 1 0 1 0 0 1 1 0 0]";
	// (X^30 + X^29 + X^26 + X^25 + X^20 + X^19 + X^15 + X^14 + X^10 + X^9 + X^8 + X^6 + X^5 + X^3)*Y^19 +
	c[19] 	= "[0 1 1 0 0 1 1 0 0 0 0 1 1 0 0 0 1 1 0 0 0 1 1 1 0 1 1 0 1 0 0 0]";
	// (X^31 + X^30 + X^27 + X^25 + X^19 + X^17 + X^16 + X^14 + X^8 + X^6 + X^4 + X^3 + X^2 + 1)*Y^20 +
	c[20] 	= "[1 1 0 0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0 0 0 0 0 1 0 1 0 1 1 1 0 1]";
	// (X^31 + X^28 + X^27 + X^25 + X^24 + X^21 + X^17 + X^16 + X^14 + X^13 + X^10 + X^8 + X^6 + X^5 + X^2)*Y^21 +
	c[21] 	= "[1 0 0 1 1 0 1 1 0 0 1 0 0 0 1 1 0 1 1 0 0 1 0 1 0 1 1 0 0 1 0 0]";
	// (X^31 + X^28 + X^25 + X^24 + X^23 + X^21 + X^20 + X^18 + X^17 + X^16 + X^15 + X^14 + X^11 + X^10 + X^9 + X^7 + X^6 + X^5 + X^3 + 1)*Y^22 +
	c[22] 	= "[1 0 0 1 0 0 1 1 1 0 1 1 0 1 1 1 1 1 0 0 1 1 1 0 1 1 1 0 1 0 0 1]";
	// (X^31 + X^29 + X^27 + X^26 + X^24 + X^23 + X^22 + X^19 + X^18 + X^17 + X^15 + X^14 + X^13 + X^12 + X^11 + X^6 + X^5 + X^4)*Y^23 +
	c[23] 	= "[1 0 1 0 1 1 0 1 1 1 0 0 1 1 1 0 1 1 1 1 1 0 0 0 0 1 1 1 0 0 0 0]";
	// (X^31 + X^30 + X^29 + X^23 + X^21 + X^19 + X^17 + X^16 + X^13 + X^11 + X^10 + X^9 + X^8 + X^6 + X + 1)*Y^24 +
	c[24] 	= "[1 1 1 0 0 0 0 0 1 0 1 0 1 0 1 1 0 0 1 0 1 1 1 1 0 1 0 0 0 0 1 1]";
	// (X^31 + X^30 + X^29 + X^28 + X^27 + X^25 + X^20 + X^18 + X^17 + X^16 + X^15 + X^14 + X^9 + X^6 + X^3 + 1)*Y^25 +
	c[25] 	= "[1 1 1 1 1 0 1 0 0 0 0 1 0 1 1 1 1 1 0 0 0 0 1 0 0 1 0 0 1 0 0 1]";
	// (X^30 + X^28 + X^25 + X^24 + X^23 + X^20 + X^18 + X^17 + X^16 + X^15 + X^12 + X^9 + X^7 + X^6 + X^5 + X^4)*Y^26 +
	c[26] 	= "[0 1 0 1 0 0 1 1 1 0 0 1 0 1 1 1 1 0 0 1 0 0 1 0 1 1 1 1 0 0 0 0]";
	// (X^30 + X^29 + X^28 + X^27 + X^26 + X^25 + X^24 + X^21 + X^20 + X^19 + X^18 + X^12 + X^8 + X^7 + X^2 + X + 1)*Y^27 +
	c[27] 	= "[0 1 1 1 1 1 1 1 0 0 1 1 1 1 0 0 0 0 0 1 0 0 0 1 1 0 0 0 0 1 1 1]";
	// (X^31 + X^29 + X^26 + X^25 + X^23 + X^19 + X^18 + X^17 + X^15 + X^13 + X^9 + X^7 + X^4 + 1)*Y^28 +
	c[28] 	= "[1 0 1 0 0 1 1 0 1 0 0 0 1 1 1 0 1 0 1 0 0 0 1 0 1 0 0 1 0 0 0 1]";
	// (X^31 + X^25 + X^24 + X^23 + X^22 + X^20 + X^17 + X^16 + X^15 + X^14 + X^13 + X^12 + X^9 + X^8 + X^3 + X^2)*Y^29 +
	c[29] 	= "[1 0 0 0 0 0 1 1 1 1 0 1 0 0 1 1 1 1 1 1 0 0 1 1 0 0 0 0 1 1 0 0]";
	// (X^31 + X^29 + X^28 + X^27 + X^24 + X^22 + X^21 + X^20 + X^16 + X^15 + X^13 + X^10 + X^7 + X^5 + X^4 + X^3 + X^2)*Y^30 +
	c[30] 	= "[1 0 1 1 1 0 0 1 0 1 1 1 0 0 0 1 1 0 1 0 0 1 0 0 1 0 1 1 1 1 0 0]";
	// (X^31 + X^26 + X^24 + X^22 + X^20 + X^15 + X^14 + X^12 + X^11 + X^9 + X^8 + X^5 + X^2 + X + 1)*Y^31 +
	c[31] 	= "[1 0 0 0 0 1 0 1 0 1 0 1 0 0 0 0 1 1 0 1 1 0 1 1 0 0 1 0 0 1 1 1]";


	stringstream caix0(c[0]);
	stringstream caix1(c[1]);
	stringstream caix2(c[2]);
	stringstream caix3(c[3]);
	stringstream caix4(c[4]);
	stringstream caix5(c[5]);
	stringstream caix6(c[6]);
	stringstream caix7(c[7]);
	stringstream caix8(c[8]);
	stringstream caix9(c[9]);
	stringstream caix10(c[10]);
	stringstream caix11(c[11]);
	stringstream caix12(c[12]);
	stringstream caix13(c[13]);
	stringstream caix14(c[14]);
	stringstream caix15(c[15]);
	stringstream caix16(c[16]);
	stringstream caix17(c[17]);
	stringstream caix18(c[18]);
	stringstream caix19(c[19]);
	stringstream caix20(c[20]);
	stringstream caix21(c[21]);
	stringstream caix22(c[22]);
	stringstream caix23(c[23]);
	stringstream caix24(c[24]);
	stringstream caix25(c[25]);
	stringstream caix26(c[26]);
	stringstream caix27(c[27]);
	stringstream caix28(c[28]);
	stringstream caix29(c[29]);
	stringstream caix30(c[30]);
	stringstream caix31(c[31]);

	caix0 >> wp[0];
	caix1 >> wp[1];
	caix2 >> wp[2];
	caix3 >> wp[3];
	caix4 >> wp[4];
	caix5 >> wp[5];
	caix6 >> wp[6];
	caix7 >> wp[7];
	caix8 >> wp[8];
	caix9 >> wp[9];
	caix10 >> wp[10];
	caix11 >> wp[11];
	caix12 >> wp[12];
	caix13 >> wp[13];
	caix14 >> wp[14];
	caix15 >> wp[15];
	caix16 >> wp[16];
	caix17 >> wp[17];
	caix18 >> wp[18];
	caix19 >> wp[19];
	caix20 >> wp[20];
	caix21 >> wp[21];
	caix22 >> wp[22];
	caix23 >> wp[23];
	caix24 >> wp[24];
	caix25 >> wp[25];
	caix26 >> wp[26];
	caix27 >> wp[27];
	caix28 >> wp[28];
	caix29 >> wp[29];
	caix30 >> wp[30];
	caix31 >> wp[31];

	ZZ_pEX auxi(32,one);

	for(int i=0; i<32; i++){
		ZZ_pEX aux(i,wp[i]);
		mod3232 += aux;
	}
}

Extractor::~Extractor() {
}

void Extractor::PolyFromBstr(ZZ_pE &x, bitstring w, int q32){
	ZZX temp;
	ZZ one;
	one = 1;

	for(int i=0; i<32;i++){
		if(w.get(i + q32)){
			ZZX t(i,one);
			temp += t;
		}
	}

	string box;
	stringstream pipe(box);
	pipe << temp;
	pipe >> x;
}

bitstring Extractor::extract(bitstring w, bitstring x) {
//	cout <<"Extractor :: w.size = "<< w.size() <<" n size"<< n<<endl;
//	cout <<"Extractor :: x.size = "<< x.size() <<" d size"<< d<<endl;
	/*if (w.size() < (size_t)n) {
		throw invalid_argument("W has wrong size");
	}*/
	/*if (x.size() != (size_t)d) {
		//cout << "(extractor.cpp:215) TO_REMOVE:X has wrong size (Extractor) x="<< x.size() << "d="<< (size_t)d <<"\n" ;
		throw invalid_argument("X has wrong size (Extractor) ");
	}*/


	// X to poly

	ZZ_pE xpoly;

	PolyFromBstr(xpoly,x,0);



	// W
	ZZ_pEX wpoly;
	ZZ_pE wpp[32];

	for(int i=0;i<32;i++){
		PolyFromBstr(wpp[i],w,32*i);
		ZZ_pEX temp(i,wpp[i]);
		wpoly += temp;
	}

	// geracao dos 4 f

	ZZ_pEX lixo;
	ZZ_pEX f1, f2, f4, f8;

	f1 = wpoly;
	DivRem(lixo, f1, f1, mod3232);
	f2 = f1 * f1;
	DivRem(lixo, f2, f2, mod3232);
	f4 = f2 * f2;
	DivRem(lixo, f4, f4, mod3232);
	f8 = f4 * f4;
	DivRem(lixo, f8, f8, mod3232);


	// f(y)

	ZZ_pE res0,res1,res2,res3;

	res0 = coeff(f1,0);
	res1 = coeff(f2,0);
	res2 = coeff(f4,0);
	res3 = coeff(f8,0);

	ZZ_pE aux = xpoly;

	for(int i=1; i<32; i++){

		res0 += aux * coeff(f1,i);
		res1 += aux * coeff(f2,i);
		res2 += aux * coeff(f4,i);
		res3 += aux * coeff(f8,i);

		aux *= xpoly;
	}


	//cout << "RES: " << res0 << "(res0) " << res1 << "(res1) " << res2 << "(res2) " << res2 << "(res2) " << "\n";

	bitstring result(128);
	

	ZZ_p one;
	one=1;

	for(int i = 0; i<32; i++){
		if(coeff(rep(res0),i) == one) result.set(i);
		if(coeff(rep(res1),i) == one) result.set(i+32);
		if(coeff(rep(res2),i) == one) result.set(i+64);
		if(coeff(rep(res3),i) == one) result.set(i+96);
	}

	/*cout << "Result: ";
	result.print();
	cout << "\n";*/


	// retornar algo de tamanho 32, porque senao da erro de tamanho errado na entrada do extractor.. provavelmente devido a realimentacao
	//bitstring bla = x;
	//cout <<"bitstring output result = "<< result.to_string()<< endl;
	return result;
}

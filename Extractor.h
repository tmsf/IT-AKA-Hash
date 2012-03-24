/*
 * Extractor.h
 *
 *  Created on: 7/Set/2009
 *      Author: Helder
 */

#ifndef EXTRACTOR_H_
#define EXTRACTOR_H_

#include "bitstring.h"
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/ZZ_pE.h>
#include <NTL/ZZ_pEX.h>
#include <iostream>
#include <sstream>

using namespace std;

NTL_CLIENT

class Extractor {
private:
	int n, k, d, l;
	float epsilon;
	ZZ_pEX mod3232;

public:
	Extractor();
	Extractor(int _n, int _k, int _d, int _l, float _epsilon);
	virtual ~Extractor();

	void PolyFromBstr(ZZ_pE &x, bitstring w, int q32);
	bitstring extract(bitstring w, bitstring x);
};

#endif /* EXTRACTOR_H_ */

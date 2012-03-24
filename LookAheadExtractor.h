/*
 * LookAheadExtractor.h
 *
 *  Created on: 7/Set/2009
 *      Author: Helder
 */

#ifndef LOOKAHEADEXTRACTOR_H_
#define LOOKAHEADEXTRACTOR_H_

#include <vector>
#include "bitstring.h"
#include "Composition.h"

using namespace std;

class LookAheadExtractor {
private:
	int n, k, d, l, t;
	float epsilon;
	Composition extw,extq;

public:
	LookAheadExtractor();
	LookAheadExtractor(int _n, int _k, int _d, int _l, int _t, float _epsilon);
	virtual ~LookAheadExtractor();

	vector<bitstring > extract(bitstring w, bitstring x);

	vector<bitstring > extract(bitstring w, bitstring x,vector < vector <bitstring> > &riS, vector < vector <bitstring> > &riMsk, vector<  vector <bitstring> > &siS, vector < vector <bitstring> > &siMsk, vector<int> &deltas);
	vector<bitstring > extract1(bitstring w, bitstring x,vector < vector <bitstring> > riS, vector < vector <bitstring> > riMsk, vector<  vector <bitstring> > siS, vector < vector <bitstring> > siMsk,vector<int> deltas);
	vector<bitstring > alternateExtraction(bitstring w,bitstring x);
	
	
	bitstring extractHASH(bitstring w, bitstring x);
	
};

#endif /* LOOKAHEADEXTRACTOR_H_ */

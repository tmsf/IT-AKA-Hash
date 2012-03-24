/*
 * LookAheadMAC.h
 *
 *  Created on: 2009/10/02
 *      Author: Helder
 */

#ifndef LOOKAHEADMAC_H_
#define LOOKAHEADMAC_H_

#include <vector>
#include "bitstring.h"

using namespace std;

class LookAheadMAC {
private:
	int m, s, l, t;
	float epsilon, delta;

public:
	LookAheadMAC();
	LookAheadMAC(int _m, int _s, int _l, int _t, float _esplison, float _delta);
	virtual ~LookAheadMAC();

	vector<bitstring > sign(vector<bitstring > r, bitstring mu);
};

#endif /* LOOKAHEADMAC_H_ */

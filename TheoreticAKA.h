/*
 * TheoreticAKA.h
 *
 *  Created on: 2009/10/02
 *      Author: Helder
 */

#ifndef THEORETICAKA_H_
#define THEORETICAKA_H_

#include <string>
#include <vector>
#include "bitstring.h"

using namespace std;
/*
#define m   146
#define t   584// (4 * m)
#define tau 160016 //(l * t)
#define d   149675
#define d2  181882
#define l2  128
#define s   74752//(2 * m * l2)
*/

#define epsilon2 128
#define delta2   128

class TheoreticAKA {
private:
	int n, k, l,t;
	float epsilon, delta;

	bitstring w, x_auth, x_key, r;
	/*vector< vector< bitstring > > siS;
	vector< vector< bitstring > > riS;
	vector <int> deltas;
*/

public:
	vector<bitstring > r_auth;
	
	enum StateValue {
		Initialized,
		KeyDerived,
		KeyConfirmed,
		KeyRefuted
	};

	struct State {
	private:
		friend class TheoreticAKA;
		State(StateValue st);
	public:
		StateValue value;
		string to_string();
	};


	StateValue state;

	TheoreticAKA();
	TheoreticAKA(int _n, int _k, int _l, float _epsilon, float _delta);
	virtual ~TheoreticAKA();

	State getState();

	void setSecret(bitstring w);
	bitstring getAuth(vector< vector< bitstring > > &siS,vector< vector< bitstring > > &siMsk, vector< vector< bitstring > > &riS,vector< vector< bitstring > > &riMsk, vector <int> &deltas);
	void setAuth(bitstring auth);
	pair<bitstring, vector<bitstring > > getKey(vector< vector< bitstring > > siS,vector< vector< bitstring > > siMsk, vector< vector< bitstring > > riS,vector< vector< bitstring > > riMsk,vector <int> deltas);
	bool setKey(bitstring key, vector<bitstring > sig);
};

#endif /* THEORETICAKA_H_ */

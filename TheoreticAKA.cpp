/*
 * TheoreticAKA.cpp
 *
 *  Created on: 2009/10/02
 *      Author: Helder
 */

#define NLA 262144
#define KLA 181882
#define DLA 165383
#define LLA 128
#define TLA 128
#define NKEY 262144 
#define KKEY 21866
#define DKEY 146
#define LKEY 128
#define MMAC 146
#define SMAC 74752
#define LMAC 128
#define TMAC 584
//#define 
//#define
//#define

#include <iostream>
#include <stdexcept>

#include "Extractor.h"
#include "LookAheadExtractor.h"
#include "LookAheadMAC.h"

#include "TheoreticAKA.h"
#include "Composition.h"

TheoreticAKA::TheoreticAKA() {
}

TheoreticAKA::TheoreticAKA(int _n, int _k, int _l, float _epsilon, float _delta) {
	n = _n;
	k = _k;
	l = _l;
	epsilon = _epsilon;
	delta = _delta;
	t=584;
	state = TheoreticAKA::Initialized;
}

TheoreticAKA::~TheoreticAKA() {
}

void TheoreticAKA::setSecret(bitstring _w) {
	w = _w;
}

TheoreticAKA::State TheoreticAKA::getState() {
	TheoreticAKA::State st(state);

	return st;
}

bitstring TheoreticAKA::getAuth(vector< vector< bitstring > > &siS,vector< vector< bitstring > > &siMsk, vector< vector< bitstring > > &riS,vector< vector< bitstring > > &riMsk,vector <int> &deltas) {
	cout << " TheoreticAKA::getAuth" << endl;
	x_auth = bitstring(131072, rand()); // TODO d=165383 -> 2^17 ou talvez 2^18?
	
	LookAheadExtractor *ext_auth = new LookAheadExtractor(n, k, (int) x_auth.size(), l, t, epsilon2);//TODO t= 10 in test mode should be -> t=584
	r_auth = ext_auth->extract(w, x_auth,siS,siMsk,riS,riMsk,deltas);
	
	delete ext_auth;

return x_auth; 
}

void TheoreticAKA::setAuth(bitstring auth) {

cout << " TheoreticAKA::setAuth"<<endl;

	x_key = bitstring(256, rand()); // d=146 -> 256 

	Composition *subext = new Composition(l,w,x_key,12); // TODO delta 
	r = subext->extract();
	
	x_auth = bitstring(auth);
	
	state = TheoreticAKA::KeyDerived;
	
	delete subext;
}

pair<bitstring, vector<bitstring > > TheoreticAKA::getKey(vector< vector< bitstring > > siS, vector< vector< bitstring > > siMsk,vector< vector< bitstring > > riS,vector< vector< bitstring > > riMsk,vector <int> deltas) {
	cout << " TheoreticAKA::getKey"<<endl;

	LookAheadExtractor *ext_auth = new LookAheadExtractor(n, k,(int) x_auth.size(), l, t, epsilon2); // TODO t=584
	
	r_auth = ext_auth->extract1(w, x_auth,siS,siMsk,riS,riMsk,deltas); //(x_auth,siS, riS,deltas) are equivalent to X_auth from the original one.

	LookAheadMAC *mac = new LookAheadMAC(146, 74752, l, t, epsilon2, delta2); // TODO t=584

	vector<bitstring > sig = mac->sign(r_auth, x_key);
	pair<bitstring, vector<bitstring > > result(x_key, sig);
	
	delete mac;
	delete ext_auth;
	return result;
}

bool TheoreticAKA::setKey(bitstring key, vector<bitstring > sig) {
cout << "TheoreticAKA::setKey"<<endl;
cout << "key.size() = "<< key.size()<<endl;
	if (key.size() < (size_t)DKEY) {
		throw invalid_argument("Xauth has wrong size");
	}
/*	if (sig.size() < (size_t)(2 * 146)) {
		throw invalid_argument("Sigma has wrong size");
	}*/
	if (sig[0].size() != (size_t)l) {
		throw invalid_argument("Sigma elements have wrong size");
	}

	x_key = bitstring(key);

	Composition *msk_ext_key;
	LookAheadMAC *mac = new LookAheadMAC(146, 74752, l, t, epsilon2, delta2);
	vector<bitstring > sig2 = mac->sign(r_auth, x_key);// ({0,1}^256)^584 x {0,1}
	
	delete mac;
	
	if (sig==sig2) {
	
		state = TheoreticAKA::KeyConfirmed;
		
		msk_ext_key = new Composition(l,w,key,12); //TODO delta
		msk_ext_key->creat_Composition();
		r= msk_ext_key->extract();
		
		delete msk_ext_key;
	}
	else {
		state = TheoreticAKA::KeyRefuted;
	} 


	return (state== TheoreticAKA::KeyConfirmed);
}

/************ TheoreticAKA::State ************/

TheoreticAKA::State::State(StateValue st) {
	value = st;
}

string TheoreticAKA::State::to_string() {
	switch (value) {
		case Initialized:
			return "Initialized";
		case KeyDerived:
			return "KeyDerived";
		case KeyConfirmed:
			return "KeyConfirmed";
		case KeyRefuted:
			return "KeyRefuted";
		default:
			return "Invalid State";
	}
}



int main(){

		srand((unsigned)time(NULL));
		bitstring w((size_t)262144, rand());	
		
		TheoreticAKA *alice = new TheoreticAKA(262144, 181882, 256, 0, 0);

		TheoreticAKA  *bob  = new TheoreticAKA(262144, 181882, 256, 0, 0);
		alice->setSecret(w);
		bob->setSecret(w);
		
		cout << "   Alice: " << (alice->getState()).to_string() << endl;
		cout << "   Bob: " << (bob->getState()).to_string() << endl;
				

		vector< vector< bitstring > > siS;
		vector< vector< bitstring > > riS;
		vector< vector< bitstring > > siMsk;
		vector< vector< bitstring > > riMsk;

		vector <int> deltas;
		bitstring x_auth  = bob->getAuth(siS,siMsk,riS,riMsk,deltas);
		//EveAttack(x_auth);

		
		alice->setAuth(x_auth);
		cout << "   Alice: " << (alice->getState()).to_string() << endl;
		cout << "   Bob: " << (bob->getState()).to_string() << endl;
			
		pair<bitstring, vector<bitstring > > x_key = alice->getKey(siS,siMsk,riS,riMsk,deltas);
		
		//EveAttack(x_key.first);
		//EveAttack(x_key.second);
		bob->setKey(x_key.first, x_key.second);

		cout << "   Alice: " << (alice->getState()).to_string() << endl;
		cout << "   Bob: " << (bob->getState()).to_string() << endl;
		
		// needed?
		//delete alice;
		//delete bob;
		cout << "--------------------------------------------------"<<endl;


}

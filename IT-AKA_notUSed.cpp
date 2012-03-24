//============================================================================
// Name        : IT-AKA.cpp
// Author      : Hélder Pereira
// Version     :
// Copyright   :
// Description : Main
//============================================================================

#include <iostream>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include "bitstring.h"

#include "TheoreticAKA.h"

#define N 262144
#define K 181882
#define L 128

using namespace std;

void EveAttack(bitstring& x);
void EveAttack(vector<bitstring >& x);

int main() {
	try {
		srand((unsigned)time(NULL));
		bitstring w((size_t)N, rand());


		TheoreticAKA alice(N, K, L, 0, 0), bob(N, K, L, 0, 0);

		alice.setSecret(w);
		bob.setSecret(w);
		cout << "Checkpoint 0" << endl;
		cout << "   Alice: " << alice.getState().to_string() << endl;
		cout << "   Bob: " << bob.getState().to_string() << endl;
		

		vector< vector< bitstring > > siS;
		vector< vector< bitstring > > riS;
		vector <int> deltas;
		bitstring x_auth  = bob.getAuth(siS,riS,deltas);
		//EveAttack(x_auth);
		cout << "before setAuth"<<endl;
		alice.setAuth(x_auth);
		cout << "Checkpoint 1" << endl;
		cout << "   Alice: " << alice.getState().to_string() << endl;
		cout << "   Bob: " << bob.getState().to_string() << endl;
		
		pair<bitstring, vector<bitstring > > x_key = alice.getKey(siS,riS,deltas);
		//EveAttack(x_key.first);
		//EveAttack(x_key.second);
		cout <<" Before setKey"<<endl;
		bob.setKey(x_key.first, x_key.second);
		cout << "Checkpoint 2" << endl;
		cout << "   Alice: " << alice.getState().to_string() << endl;
		cout << "   Bob: " << bob.getState().to_string() << endl;
	}
	catch (invalid_argument e) {
		cout << "ERROR: " << e.what() << endl;
	}

	return 0;
}

void EveAttack(bitstring& x) {
	x.flip();
}

void EveAttack(vector<bitstring >& x) {
	x[0].flip();
}

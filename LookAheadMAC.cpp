/*
 * LookAheadMAC.cpp
 *
 *  Created on: 2009/10/02
 *      Author: Helder
 */

#include <stdexcept>
#include <iostream>
#include "LookAheadMAC.h"

LookAheadMAC::LookAheadMAC() {
}

LookAheadMAC::LookAheadMAC(int _m, int _s, int _l, int _t, float _epsilon, float _delta) {
	m = _m;
	s = _s;
	l = _l;
	t = _t;
	epsilon = _epsilon;
	delta = _delta;

//	cout << "lookaheadMAC: m: "<< m <<" s: "<< s <<" l: "<<l<<" t: "<<t <<endl;

}

LookAheadMAC::~LookAheadMAC() {
}

vector<bitstring > LookAheadMAC::sign(vector<bitstring > r, bitstring mu) {
	cout << "lookaheadMAC::sign"<<endl;
	if (r.size() < (size_t)t) {
		throw invalid_argument("R has wrong size");
	}
	if (r[0].size() != (size_t)l) {
		throw invalid_argument("R elements have wrong size");
	}
	if (mu.size() < (size_t)m) {
		throw invalid_argument("Mu has wrong size");
	}
	

	//cout << "lookahead r.sizet size "<<endl;
	vector<bitstring > result;

	//for (int i = 1; i <= m; i++) {

	int counter=0;
	cout << "mu size "<< mu.size() << endl;
	cout << "r size "<< r.size() << endl;
	
//	for (int i = 0; i < (int) mu.size(); i++) {// TODO remove
	for (int i = 1; i < 146; i++) {// TODO 146*4 = 584! this is the right one
 	int bi;
	//cout << "check "<<i<<endl;
	bool b = mu.get(i-1);//= mu[i] ? 1 : 0;
		
		if(b==true) bi = 1;
		if(b!=true) bi = 0;
	
	//	bitstring as = r[4*i-3+bi];
		
			
		result.push_back(r[4 * i - 3 + bi]);
		result.push_back(r[4 * i - bi]);
	//cout << "check "<<i<<endl;
	counter ++;

	}
//	cout << "i'm of of mac.sign counter = "<<counter <<endl;
/*	for(int j=0;j<m;j++){
	bitstring resulti= result.at(j);
	cout << resulti.to_string() << endl;
	}
*/
//cout << "result size of mac.sign output " << result.size() << endl;
	
/*	for (int i=0;i<(counter*2);i++){

	cout << "resSigX= "<<result.at(i).to_string()<<endl; 
	}*/


return result;
}


/*
int main(){
srand(time(0));


LookAheadMAC la2 = LookAheadMAC(146, 74752, 256, 584, 0, 0);
LookAheadMAC la1 = LookAheadMAC(146, 74752, 256, 584, 0, 0);
//LookAheadMAC(int _m, int _s, int _l, int _t, float _epsilon, float _delta) {

vector< vector<bitstring> > v;
		vector <bitstring> b;

	for (int i=0;i<584; i++){
		//for(int j=0;j<256,j++)
		b.push_back(bitstring(256,rand()));
	//v.push_back(b);
	}


	for (int i=0;i<584; i++){
		cout << "b = "<<b.at(i).to_string()<<endl;	
	}

	bitstring sk = bitstring(256,rand());
	
	vector<bitstring> s1=la1.sign(b,sk);
	vector<bitstring> s2=la2.sign(b,sk);

		bool flag =true;
	for(int f=0;f<(int)s1.size(); f++){
//	cout << "sig1 " << sig.at(f).to_string() << "\n";//sig2 "<< sig2.at(f).to_string() <<"\n i= "<<f<<" "<<endl;  
	
	if ((bitstring) s1.at(f) != (bitstring)s2.at(f) ){ cout << "why? why?! error at "<<f<<endl;
	//cout << "sig1 " << sig.at(f).to_string() << "\n";//sig2 "<< sig2.at(f).to_string() <<"\n i= "<<f<<" "<<endl;  

		flag = false;
		}


	//else cout << "wee"<<endl;
	
	}

	if(flag) {cout << "wee \n\n\n\n\n\n\n";}


}*/

/*
 * LookAheadExtractor.cpp
 *
 *  Created on: 7/Set/2009
 *      Author: Helder
 */

// look ahead extractor values
#define N 262144
#define K 181882
#define D 165383
#define L 160
#define T 584
#define NW 262144
#define KW 149675
#define DW 161
#define LW 128
#define NQ 165255
#define KQ 171
#define DQ 161
#define LQ 128
//define



/*
*/

#include <stdexcept>
#include "Extractor.h"
#include "LookAheadExtractor.h"
#include "Composition.h"
#include "translator.h"
#include "amd64/crypto_hash_sha256.h"



LookAheadExtractor::LookAheadExtractor() {
}

LookAheadExtractor::LookAheadExtractor(int _n, int _k, int _d, int _l, int _t, float _epsilon) {
	n = _n;
	k = _k;
	d = _d;
	l = _l;
	t = _t;
	epsilon = _epsilon;

}

LookAheadExtractor::~LookAheadExtractor() {

}

vector<bitstring > LookAheadExtractor::extract1(bitstring w, bitstring x, vector< vector <bitstring> > extwSVector,vector< vector <bitstring> > extwMskVector, vector< vector <bitstring> > extqSVector,vector< vector <bitstring> > extqMskVector, vector<int> deltas) {
	cout << "LookAheadExtractor::extract1 "<<endl;
	
	vector<bitstring > result;

	bitstring q;
	bitstring si;
	bitstring ri;

	
	 q  = x.subbits(0,((int)x.size()-l)); // X=[    q       | S1=256bits  ]
	 si = x.subbits(((int)x.size()-l), l);

	Composition *msk_w = new Composition(l,w,si,extqSVector.at(0),extqMskVector.at(0),deltas.at(0));// TODO idem + random delta. len(si) = outputsize 
	ri= msk_w->extract();
	result.push_back(bitstring(ri));
	
	delete msk_w;

	for (int i = 1; i < t; ++i) { 
	
		Composition *temp_extq = new Composition(l,q,ri, extwSVector.at(i-1),extwMskVector.at(i-1),deltas.at(i)); // Todas as Compositions sao independentes apenas usam um S_0 que depende da anterior.
		
		si= temp_extq->extract();
		
		delete temp_extq;
		Composition *temp_extw = new Composition(l,w,si, extqSVector.at(i),extqMskVector.at(i),deltas.at(i)); // Todas as Compositions sao independentes apenas usam um S_0 que depende da anterior.	
		ri=temp_extw->extract();
		result.push_back(bitstring(ri));
		delete temp_extw;
	}


return result;
}




/***************************************************/






vector<bitstring > LookAheadExtractor::extract(bitstring w, bitstring x,vector< vector< bitstring > > &extqSVector,vector< vector< bitstring > > &extqMskVector,vector< vector< bitstring > > &extwSVector,vector< vector< bitstring > > &extwMskVector, vector<int> &deltas) {
	
	vector<bitstring > result;
	bitstring q = x.subbits(0,((int)x.size()-l)); // X=[    q       | Si[1]=256bits  ]
	bitstring si = x.subbits(((int)x.size()-l), l);
	
	/* ExtW*/
	int delta=4;

	Composition *msk_w = new Composition(l,w,si,delta);// TODO idem + random delta. len(si) = outputsize 
	msk_w->creat_Composition();

	vector<bitstring> extw_S = msk_w->S; 
	vector<bitstring> extw_aMsk = msk_w->Msk; 

	
	extwSVector.push_back((vector <bitstring>)extw_S);//extwSVector[0]= extw.S[];
	extwMskVector.push_back((vector <bitstring>)extw_aMsk);
	
	deltas.push_back(4); // TODO must be random and one delta for each "extractorComposition", 2 vectors for ri and si.
	
	bitstring ri= msk_w->extract();
	result.push_back(ri);	 // result[0]= ri;
	//bitstring sit;

	
	for (int i = 2; i <= t; ++i) {
		delta = 4;
		
		deltas.push_back(delta); // TODO must be random and one delta for each "extractorComposition", 2 vectors for ri and si.

		Composition *temp_extq = new Composition(l,q,ri,delta); // Todas as Compositions sao independentes apenas usam um S_0 que depende da anterior.
	
		temp_extq->creat_Composition();

		extqSVector.push_back((vector <bitstring>) temp_extq->S); // extqSVector[i] = extq.S[];
		extqMskVector.push_back((vector <bitstring>) temp_extq->Msk); //extwSVector[i]= extw.S[];		

		bitstring si= temp_extq->extract();

		delete temp_extq;
		

		Composition *temp_extw = new Composition(l,w,si,delta);
		temp_extw->creat_Composition();
		
			extwSVector.push_back((vector <bitstring>) temp_extw->S); //extwSVector[i]= extw.S[];
			extwMskVector.push_back((vector <bitstring>) temp_extw->Msk); //extwSVector[i]= extw.S[];
		
		ri=temp_extw->extract();
		
		result.push_back(bitstring(ri)); 
		
		delete temp_extw;	
	}
		


return result;
}


bitstring LookAheadExtractor::extractHASH(bitstring w, bitstring x){
	
//	bitstring Composition::hashBitstring(bitstring b){

	/*
	 in this function we transform bitstring objects in hexadecimal values, apply the sha256 function and reconvert to bitstring. 
	*/

	char * pEnd;
	char *hashInput;
	long int li;
	int aa=0;
	int i=0;
	unsigned char *str1,*hashOutput;
	string strTemp;

	
	bitstring b=  bitstring(size_t(w.size()+x.size())).concat(w,x);
	
	
	translator *trl = new translator(b);
	string str01 = trl->getHexstring(); // bitstring value in hexadecimal form 0xDEADBEEF

	delete trl;

	//cout <<" string size"<< str01.size() <<endl;
	//cout << "string str01 : " << str01<<endl;
	char *ch = (char*) str01.c_str();
	hashInput=(char*) malloc(sizeof(char)*(b.size()/4));


		while(aa<((int)b.size()/4)){	
			char letra[1];
	 		letra[0] = ch[aa];
			li = strtol(letra,&pEnd,16); 

			hashInput[i]=*(reinterpret_cast <const unsigned char*> (&li));

			//cout << "passei aqui "<<i<<endl;
			aa=aa+1;
			i++;// foi alterado agr
		}

	str1=(unsigned char*)malloc(sizeof(unsigned char)*(b.size()/4));

	hashOutput=(unsigned char*)malloc(sizeof(const unsigned char)*(32));


	/*******************************dont touch below this line**********************************************/

		string hashOutput1=crypto_hash_sha256(hashInput);
		crypto_hash_sha256((unsigned char* )hashOutput,(const unsigned char*)hashInput,(unsigned long long)str01.size());

	stringstream ss (stringstream::in | stringstream::out);

		unsigned int lix;
		int ii=0;

		char temp1,temp0;

		while(ii<(32)){// TODO 32 para 256bits (length genérica do output em hexadecimal da hash function) / 2 - cada long tem 2 elementos hex
			lix = hashOutput[ii]; // TODO está a usar a versao de string. a outra estoura-se toda e nao da valores  iguais para o mesmo input.

			ss<< std::setw( 2 ) << std::setfill( '0' ) <<std::hex<< (lix );
			ss.get(temp1);
			ss.get(temp0);

			strTemp.push_back(temp1);
			strTemp.push_back(temp0);

			ii++;
		}

	translator *t = new translator((string)strTemp);
	bitstring result = t->getBitstring(); // here is the output of hash! :P finally!

	delete t;

	free(hashInput);
	free(str1);
	free(hashOutput);

	return result;
	
	
}


vector<bitstring > LookAheadExtractor::alternateExtraction(bitstring w,bitstring x){
	//S_1 
	//Q
	cout << "mudar o _t_ e _l_ para dinamico e nao 584 e 256"<<endl;
	int l = 256;
	int t = 584;
	
	vector<bitstring > result;
	
	bitstring q = x.subbits(0,((int)x.size()-l)); // X=[    q       | S1  ]
	bitstring si = x.subbits(((int)x.size()-l), l); // S1

	bitstring ri; //= bitstring(size_t(100000));
//	bitstring r_1 = extractHASH(w,s_1);
//	bitstring s_2 = extractHASH(q,r_1);
	
	for (int i = 2; i <= t; ++i) { 
		
		ri = extractHASH(w,si);
		
		result.push_back(bitstring(ri)); 
		
		si = extractHASH(q,ri);
		
	}
	
	bitstring rt = extractHASH(w,si);
	result.push_back(rt);
	
	return result;
}


void printVec(vector <bitstring> vec){
	
	for(int i=0;i<(int)vec.size();i++){
		cout << vec.at(i).to_string()<< endl;
	}
	
}




int main(){

srand(time(0));
	
LookAheadExtractor *la = new LookAheadExtractor();
	
	bitstring x_auth = bitstring((size_t)8192,rand()); //TODO must have at least 256bits for S1 and at least 512 for Q to create a Composition

	bitstring w = bitstring((size_t)8192,rand());

	
	vector< bitstring > vb = la->alternateExtraction(w,x_auth);
	
	printVec(vb);
	cout << "MUDAR O EXTRACTHASH PARA O SCOPE EXTERNO"<< endl;
}

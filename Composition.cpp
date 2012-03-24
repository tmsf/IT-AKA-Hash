#include <fstream>
#include "bitstring.h"
#include "sha1.h"
#include "MySHA.h"
#include "Composition.h"
#include "translator.h"
#include "amd64/crypto_hash_sha256.h"
using namespace std;

//NTL_CLIENT

Composition::Composition(){}
Composition::~Composition(){}

Composition::Composition( int outputlength, bitstring w_, bitstring x_,vector <bitstring> rs,vector <bitstring> aMsk,int delta_){
//srand(time(0));

	isHashed=false;
	delta=delta_;
	outsize=outputlength;
	n=(int)w_.size();
	if((n % outsize)==0){
		
		l=n/outsize;

		bsize=outsize; //TODO deverá ser trocado pelo tamanho ou 160 (sha1) ou 256 (sha256)
	 	tsize=(int) round(log2(n));
		//cout<< "tsize "<< tsize<<endl;	
	//	cout << "this is really good number\n("<<n<<")/"<<outsize<<"= "<< (n/outsize)<< "\n";
	//	cout << "log de "<< n<< " = "<< tsize <<"\n"; 
	}
	else {cout << "this is an cout exception\n\n\n";}


	h.insert(h.begin(),l,bitstring((size_t) bsize));

	hcopy.insert(hcopy.begin(),l,bitstring((size_t) bsize));
	
	S.insert(S.begin(),l,bitstring((size_t) bsize)); 
	
	status.insert(status.begin(),(tsize+1),1);
	
	Msk.insert(Msk.begin(),(tsize+1),bitstring((size_t) bsize));

	int acc=0;
	for(int i=0;i<l;i++){
		x.insert(x.begin(),1,((bitstring) (w_).subbits(acc,outsize)));  
		acc=acc+outsize;
	
	}

		//cout << "chekc size of the rs in creat_Composition(rs) = "<<rs.size()<<" delta"<<delta<<"\n";
	creat_Composition(rs,aMsk);
		//cout << "creat_Composition(vector <bistrstring> rs) was executed correctly \n";
}


Composition::Composition( int outputlength, bitstring w_, bitstring x_,int delta_){
//srand(time(0));


	isHashed=false;
	n=(int) w_.size(); 
	delta=delta_;
	outsize=outputlength;

	if((n % outsize)==0){
		//cout << "this is really good number\n("<<n<<")/"<<outsize<<"= "<< (n/outsize)<< "\n";
		
		l=n/outsize;
		bsize=outsize; 
	 	tsize=(int) round(log2(n));
		
		//cout<< "tsize "<< tsize<<endl;	
		//cout << "l= "<< l << endl;
		//cout <<"X input" << x_.to_string()<<endl;
		//cout << "log de "<< n<< " = "<< tsize <<"\n"; 
		bitstring xx = x_.subbits(0,(size_t) bsize);
		//cout << "X "<< xx.to_string()<<endl;
		//cout << "X must be at least "<<bsize << endl;
		
		init(w_,xx);

	}
	else {
		cout << "this is an exception\n\n\n";
	}
}

void Composition::init(bitstring xi,bitstring s0){
int acc=0;

	//srand(time(0));

	//cout << "l= "<< l << " delta= "<<delta <<"\n";  

	/*initializations*/
	h.insert(h.begin(),l,bitstring((size_t) bsize));

	hcopy.insert(hcopy.begin(),l,bitstring((size_t) bsize));
	
	S.insert(S.begin(),l,bitstring((size_t) bsize));
	
	status.insert(status.begin(),(tsize+1),1);
	
	Msk.insert(Msk.begin(),(tsize+1),bitstring((size_t) bsize));


		//cout<< "Msksize "<< Msk.size()<<endl;	
	
	for(int i=0;i<l;i++){
	
		x.insert(x.begin(),1,((bitstring) xi.subbits(acc,outsize)));  
		acc=acc+outsize;
	
	}
	
S_0=s0;
//	bitstring((size_t) bsize,rand()); // TODO esta incialização nao será para o valor de X \in {0,1}^d ? 

}


int Composition::vTwo(int i){
int out=-1;
int tempi =  i;
int vtemp = round(log2(i));
double pow2c;

	if(i >=1){	
		for(int c=vtemp;c>=0;c--){
			pow2c = pow((double)2,c);
				if((tempi % (int)pow2c)==0) 
					out=c;
		}	
	}

//cout << "vtwo("<<i<<") = "<< vtemp << "\n";

return vtemp;
}


bitstring Composition::concat(bitstring a,bitstring b){
int asize,bisize,resize;
bool bita,bitb;
bitstring resa,resb; 	

	asize = a.size();
	bisize = b.size();
	resize = asize+bisize;

	resa = bitstring((size_t) resize);
	resb = bitstring((size_t) resize);
	resa.reset();
	resb.reset();	

	/*these 2 cicles are inefficient but they work*/
	for(int aa=0;aa<asize;aa++){
		
		bita=a.get(aa);
		resa.set(aa,bita);
	}

	resa <<=(bisize);
	
	for(int bb=0;bb<bisize;bb++){	
		
		bitb=b.get(bb);
		resb.set(bb,bitb);
	}

resa|=resb;
//cout << "concat()"<<endl;
return resa;
}

bitstring myXOR(bitstring a, bitstring b){

size_t asize,bisize;
asize = a.size();
bisize = b.size();

bitstring *aa = new bitstring(a);
bitstring *bb = new bitstring(b);
//aa->reset();
//bb->reset();

	//aa= a.subbits(0,asize);
	//bb= b.subbits(0,bisize);

*aa^=*bb;

delete bb;
//cout << "myXOR()"<<endl;
return *aa;
}




bitstring Composition::hashBitstring(bitstring b){

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
	
	while(ii<(outsize/8)){// TODO 32 para 256bits (length genérica do output em hexadecimal da hash function) / 2 - cada long tem 2 elementos hex
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


void Composition::creat_Composition(){

 
	for(int jt=0;jt <= tsize;jt++){
		status[jt]= UNDEFINED;
	} //check

S[l-delta]=S_0;
status[vTwo((l-delta))]=BEINGDEFINED;

//bitstring(bsize, (unsigned long) rand()) TODO decidir que valor vai aparecer aqui! X\in {0,1}^d ou vai ser no h[0].

	for(int i=(l-delta-1); i>=1; i--){

		j=vTwo(i);
		
		if(status[j]==UNDEFINED){

			S[i]= bitstring((size_t) bsize, rand());
			//cout << "S["<<i<<"]= "<< S[i].to_string() << endl; 
			status[j]=BEINGDEFINED;				
			bitstring *stemp=new bitstring(S[i]);
			bitstring *xtemp= new bitstring(x[i]);

			bitstring ctemp=concat(*stemp,*xtemp);
			delete stemp;
			delete xtemp;
			h[i] = hashBitstring(ctemp); // H_K(Si++xi)
			
			if (h[i]!= hashBitstring(ctemp)) cout << "\n\n\n\n\n FAIL!\n\n\n "<<endl; // TODO apenas para verificar que a hash é deterministica (uma das versoes do NaCl n tá a funcionar como deve.
			i_linha = i + 1;
			j_linha = vTwo(i_linha);

				
			while(status[j_linha] != BEINGDEFINED ){

				bitstring *Compositiontemp = new bitstring(Msk[vTwo(i_linha)]);	
				bitstring *htemp    = new bitstring(h[(i_linha-1)]);	
				
				bitstring *xor0temp = new bitstring(myXOR(*htemp,*Compositiontemp));
				bitstring *xi_linha = new bitstring(x[i_linha]);
				bitstring *con0temp = new bitstring(concat(*xor0temp,*xi_linha));
					
				h[i_linha] = hashBitstring(*con0temp);
					
				i_linha++;
				j_linha = vTwo(i_linha);
				
				delete Compositiontemp;
				delete htemp;
				delete xor0temp;
				delete xi_linha;
				delete con0temp;
						
			}
		
			Msk[j_linha] = myXOR(bitstring(h[i_linha-1]),bitstring(S[i_linha])); 
			status[j_linha]= DEFINED;			
		}	

	}

i_linha=1; 
j_linha=0;
	

	while(status[j_linha]!=BEINGDEFINED){
	
		bitstring *xor1temp = new bitstring(myXOR(bitstring(h[i_linha-1]),bitstring(Msk[vTwo(i_linha)])));
		bitstring *con1temp = new bitstring(concat(*xor1temp,bitstring(x[i_linha]))); 
		
		h[i_linha] = hashBitstring(*con1temp);
		
		i_linha++;
		j_linha=vTwo(i_linha);
		delete xor1temp;
		delete con1temp;
	} 


Msk[j_linha]=myXOR(bitstring(h[i_linha-1]),bitstring(S[i_linha]));
status[j_linha]=DEFINED;

	for(int xx=0;xx<=tsize;xx++)
		if(status[xx]==UNDEFINED){
			Msk[xx]=bitstring((size_t) bsize,rand());    
			//cout << "Msk["<<xx<<"]= rand()"<<endl;
			}


for(int ff=0; ff<(int)S.size();ff++){
	copyS.push_back(bitstring(S.at(ff)));
	}

}


vector<bitstring> Composition::getS(){

	return copyS;

}


void Composition::copyH(){
	for(int i=0; i<l;i++){	
		hcopy[i]=bitstring(h[i]);
	}

}


/* */
void Composition::creat_Composition(vector <bitstring> rs, vector <bitstring> aMsk){

//cout << "creat_Composition()"<< endl;
 
	for(int jt=0;jt <= tsize;jt++){
		status[jt]= UNDEFINED;
	} //check

//cout << "Si XXXXX size is before "<< S.size()<<endl;

//cout << "checkpoint Composition1"<< endl;	
S[l-delta]=rs.at(l-delta);//rs[l-delta];
status[vTwo((l-delta))]=BEINGDEFINED;
/*
cout << "size do rs "<<rs.size()<< endl;
cout << "size do tsize " << tsize << endl;	
cout << "size do bsize " << bsize << endl;	
cout << "size do lsize " << l<< endl;	*/
//bitstring(bsize, (unsigned long) rand()) TODO decidir que valor vai aparecer aqui! X\in {0,1}^d ou vai ser no h[0].

	for(int i=(l-delta-1); i>=1; i--){

	j=vTwo(i);
		if(status[j]==UNDEFINED){
			// Si comes from rs[i].			
			S[i]= rs.at(i);//bitstring((size_t) bsize, rand()); 
			status[j]=BEINGDEFINED;				
			
			bitstring *stemp= new bitstring(S[i]);
			bitstring *xtemp= new bitstring(x[i]);
			bitstring *ctemp= new bitstring(concat(*stemp,*xtemp));
			
			//cout <<"ctemp = "<< ctemp.to_string() << endl;
			//cout << "xtemp" << xtemp->to_string() <<endl;
			//cout << "stemp" << ctemp.to_string() <<endl;
			h[i] = hashBitstring(*ctemp); // H_K(Si++xi)
			//cout << "h["<<i<<"]= "<< h[i].to_string() << endl;	
			i_linha = i + 1;
			j_linha = vTwo(i_linha);
			
			delete stemp;
			delete xtemp;
			delete ctemp;
				
			while(status[j_linha] != BEINGDEFINED ){

				bitstring *Compositiontemp= new bitstring(Msk[vTwo(i_linha)]);	
				bitstring *htemp   = new bitstring(h[(i_linha-1)]);	
				
				bitstring *xor0temp = new bitstring(myXOR(*htemp,*Compositiontemp));
				bitstring *xi_linha = new bitstring(x[i_linha]);
				bitstring *con0temp = new bitstring(concat(*xor0temp,*xi_linha));
					
				h[i_linha] = hashBitstring(*con0temp);
					
				i_linha++;
				j_linha = vTwo(i_linha);
				
				delete Compositiontemp;
				delete htemp;
				delete xor0temp;
				delete xi_linha;
				delete con0temp;		
			}
		
			Msk[j_linha] = myXOR(bitstring(h[i_linha-1]),bitstring(S[i_linha])); 
			status[j_linha]= DEFINED;			
		}	

	}

i_linha=1; 
j_linha=0;
	

	while(status[j_linha]!=BEINGDEFINED){
	
		bitstring *xor1temp = new bitstring(myXOR(bitstring(h[i_linha-1]),bitstring(Msk[vTwo(i_linha)])));
		bitstring *con1temp = new bitstring(concat(*xor1temp,bitstring(x[i_linha]))); 
		
		h[i_linha] = hashBitstring(*con1temp);
		
		i_linha++;
		j_linha=vTwo(i_linha);
		delete xor1temp;
		delete con1temp;
		
	} 


Msk[j_linha]=myXOR(bitstring(h[i_linha-1]),bitstring(S[i_linha]));
status[j_linha]=DEFINED;

	for(int xx=0;xx<=tsize;xx++)
		if(status[xx]==UNDEFINED){
			//cout << "Aqui "<< xx<<endl;
			Msk[xx]=bitstring(aMsk.at(xx));//bitstring((size_t) bsize,rand());    
			//cout << "Ali"<<endl;
			//cout << "Msk["<<xx<<"]= rand()"<<endl;
			}


//cout << "SiXXXXX size after "<< S.size()<<endl;

}



/* */





bitstring Composition::creat_Digest(){

	copyH();

bitstring h0= bitstring((size_t) bsize); //arbitrally chosen bitstring  "0000000000000000000000(...)"
h0.reset();

hcopy[0]=h0; 
	
	for(int i=1;(i<l);i++){
		
		bitstring *a= new bitstring(myXOR(bitstring(hcopy[i-1]),bitstring(Msk[vTwo(i)])));
		bitstring *b = new bitstring(concat(*a,bitstring(x[i])));
		hcopy[i]=hashBitstring(*b);
		delete a;
		delete b;
	}

isHashed=true;

bitstring res = (hcopy[l-1]);

return res;
}
/**********************************************************************/


/**********************************************************************/




void Composition::toString(){
/*
for(int xz=0;xz<tsize;xz++){
	cout << "Msk["<<xz<<"]= "<< Msk[xz].to_string()<< endl;
}	

for(int y=0;y<l;y++){
	cout << "S["<<y<<"]= "<< S[y].to_string() <<endl;
	}
*/
for(int y=0;y<l;y++){
	cout << "h["<<y<<"]= "<< hcopy[y].to_string() <<endl;
}

/*for(int y=0;y<l;y++){
	cout << "x["<<y<<"]= "<< x[y].to_string() <<endl;
}


for(int xz=0;xz<tsize;xz++){
	cout << "status["<<xz<<"]= "<< status[xz]<< endl;
}

cout <<"delta = "<<delta <<" and vtwo delta= "<<vTwo(delta)<<endl;
*/
}




bitstring Composition::extract(){
bitstring res;

	if(isHashed == false){
		//cout << "Composition::extract()"<<endl;
		res=creat_Digest();
		//cout << "Composition::extract()2"<<endl;
	
	}
	else{
		res=hcopy[l-1];}

//cout << "value extracted Composition.extract() ="<< res.to_string() <<endl;
//return bitstring(256,rand());
return res;
}



/*


int main(int argc, char **argv){
srand(time(0));

bitstring x = bitstring((size_t) 512, rand());
bitstring xy = x.subbits(0,x.size());
bitstring w = bitstring((size_t) 262144, rand());
//int del= rand() %16;

Composition mh = Composition(256, w, x,4);

//vector <bitstring> vs = mh.S;

//bitstring res1 = mh.hashBitstring(x);
//bitstring res2 = mh.hashBitstring(xy);




mh.creat_Composition();
cout << "check"<<endl;
Composition mh2 = Composition(256, w, x,mh.S,mh.Msk,mh.delta);
//Composition mh2 = Composition(256, w, x,4);
//mh2.creat_Composition();




bitstring bitres = mh.creat_Digest();

bitstring bitres2 = mh2.creat_Digest();




//mh.copyH();

//mh.toString();
//mh2.creat_Composition();
//mh.copyH();
if (bitres==bitres2) cout << "Success!\n\n\n"; else{ cout << "Fail!"<<endl;


for (int i=0;i<(int)mh.Msk.size();i++){
	cout << "Msk["<<i<<"]= "<<mh.Msk.at(i).to_string()<<endl;
}

for (int i=0;i<(int)mh2.Msk.size();i++){
	cout << "Msk["<<i<<"]= "<<mh2.Msk.at(i).to_string()<<endl;
}

cout << "Digest1 = "<<bitres.to_string() <<endl;
cout << "Digest2 = "<<bitres2.to_string()<<endl;
}


//cout << "checkpoint 3 (int main()) \n"; 
//mh.toString();
//for(int kk=0;kk<mh.tsize;kk++) cout << "status["<<kk<<"]= "<< mh.status[kk] << "\n";

//mh.toString();

//cout << "-----------------------------------------------\n"; 
return 0;
}




*/





/** main 

int main(int argc, char **argv){
srand(time(0));

bitstring x = bitstring((size_t) 256, rand());
bitstring w = bitstring((size_t) 32768, rand());
int del= rand() %16;
cout << "-----------------------------------------------\n"; 

Composition mh = Composition(256, w, x,del);
cout << "-----------------------------------------------\n"; 

mh.creat_Composition();

Composition mh2 = Composition(256, w, x,mh.S,mh.delta);
cout << "-----------------------------------------------\n"; 

bitstring bitres = mh.creat_Digest();
bitstring bitres2 = mh2.creat_Digest();


for (int i=0;i<(int)mh2.x.size();i++){
	if (mh.x[i]!=mh2.x[i]){
		cout <<" FUUUUUUUUU "<<i<<endl;
		cout <<"1 "<< mh.x[i].to_string()<<endl;
		cout <<"2 "<< mh2.x[i].to_string()<<endl;
	}

}


if (bitres==bitres2){
		cout << "\n\n\nWIN!\n\n"<<endl;
	}
		cout << "del "<< del<< endl;

//mh.copyH();

//mh.toString();
//mh2.creat_Composition();
cout << "-----------------------------------------------\n"; 
//mh.copyH();
cout << "Digest1 = "<<bitres.to_string() <<endl;
cout << "Digest2 = "<<bitres2.to_string()<<endl;

//cout << "checkpoint 3 (int main()) \n"; 
//mh.toString();
//for(int kk=0;kk<mh.tsize;kk++) cout << "status["<<kk<<"]= "<< mh.status[kk] << "\n";

cout << "-----------------------------------------------\n"; 
//mh.toString();

cout << "-----------------------------------------------\n"; 
return 0;
}


  main **/

// assinatura de testes nao necessaria.
/*Composition::Composition(bitstring  w,bitstring kinp){ //mudar a assinatura para o tipo certo
//bool bit;
bitstring temp= bitstring((size_t) msize);
temp.reset();
for(int k=0;k<msize;k++) x[k]=bitstring((size_t) msize);

//cout << "w"<< w.to_string()<<endl;
//int ki=0;
//int ii=0;
	
int i=0;
int max=0;
for(;i<512;i++){
	x[i]=bitstring((size_t)msize);
	
	for(int j=0;j<512;j++){
		bool bit=w.get(max);
		
		x[i].set(j,bit);
	max++;
	}
}
	
for(int z=0; z<msize; z++) cout << "x["<<z<<"]= " << x[z].to_string()<< "\n";

key=kinp;

}*/


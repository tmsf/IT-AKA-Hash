#include <iostream>
#include <sstream>	
#include <cmath>	
#include <string.h>
#include "translator.h"
#include "bitstring.h"


translator::translator(){}
translator::~translator(){
}

/**done **/
translator::translator(bitstring a){
//cout <<"translator::translator(bitstring a);\n\n\n\n";
bites=a;
bitstr2Char(a);

}

translator::translator(string b){
hexa=b;
int size = hexa.size();
bites = bitstring((size_t) 4*size);
bites.reset();
bites=toBstr(hexa);

}

void translator::bitstr2Char(bitstring b){
int bits[4];
int size = (int) b.size();
//cout << "sadB " << b.to_string()<<endl;
if(size % 4 != 0){cout <<"TODO exception (translator.cpp line 34 )"<< endl;} // TODO trow a terrible exception

int k = size/4;
chares = string((size_t) k ,'_');
for(int j=0; j<size;){
	
	bits[0]=b.get(j);
	bits[1]=b.get(j+1);	
	bits[2]=b.get(j+2);	
	bits[3]=b.get(j+3);	
	
	j=j+4;

	char temp =array2Hex(bits);
//	x.insert(x.begin(),1,((bitstring) xi.subbits(acc,mysize)));  
	//
	chares[k-1]=temp;
	
	k--;
	}

hexa=string(chares);
//cout <<"sad "<< hexa <<endl;
}

bitstring translator::getBitstring(){return bites;}
string translator::getHexstring(){return hexa;}

char translator::array2Hex(int *array){
char res='X';
char resx[16]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

double two = (double) 2;	
int value = array[0]*pow(two,0)+array[1]*pow(two,1)+array[2]*pow(two,2)+array[3]*pow(two,3);


if(value >=0 && value <16) res=resx[value];

if(res=='X') cout <<"exc\n";//atira excepçao TODO

return res;
}

int translator::chartoBits(char izard){
 /*   ugly as hell    **/

for(int q=0;q<4;q++) arraytemp[q]=0;


int  res0[4] = {0,0,0,0};
int  res1[4] = {0,0,0,1};
int  res2[4] = {0,0,1,0};
int  res3[4] = {0,0,1,1};
int  res4[4] = {0,1,0,0};
int  res5[4] = {0,1,0,1};
int  res6[4] = {0,1,1,0};
int  res7[4] = {0,1,1,1};
int  res8[4] = {1,0,0,0};
int  res9[4] = {1,0,0,1};
int  resA[4] = {1,0,1,0};
int  resB[4] = {1,0,1,1};
int  resC[4] = {1,1,0,0};
int  resD[4] = {1,1,0,1};
int  resE[4] = {1,1,1,0};
int  resF[4] = {1,1,1,1};
/** ugly zone **/ 

int *res;

char a= izard;
	switch(a){
	case '0':
	  res=res0;
	  break;
	case '1':
	  res=res1;
	  break;
	case '2':
	  res=res2;
	  break;
	case '3':
	  res=res3;
	  break;
	case '4':
	  res=res4;
	  break;
	case '5':
	  res=res5;
	  break;
	case '6':
	  res=res6;
	  break;
	case '7':
	  res=res7;
	  break;
	case '8':
	  res=res8;
	  break;
	case '9':
	  res=res9;
	  break;
	case 'a':
	  res=resA;
	  break;
	case 'b':
	  res=resB;
	  break;
	case 'c':
	  res=resC;
	  break;
	case 'd':
	  res=resD;
	  break;
	case 'e':
	  res=resE;
	  break;
	case 'f':
	  res=resF;
	  break;
	default: 
	  res=res0;
	}

for(int k=0;k<4;k++) 
	arraytemp[k]=res[k];

return *res;
}

void translator::valuetosha(){

cout <<"tostring():";
cout << "0x";
for(int i=(bites.size())/4;i>=0;i--){
cout << chares[i];
}
cout <<"\n";

}

bitstring translator::toBstr(string arr){
int i=arr.size()-1;
int j=0;
bitstring result=bitstring((size_t)256); // TODO generalizar
result.reset();	
	

	if(arr.size()>0){ 
		//cout << "arr.size " << arr.size() <<endl;
		
		while(i>=0 || j<((int)arr.size())){ // Array é invertido aqui
		
		chartoBits(arr[i]);
		if(arraytemp[3]==1) result.set(4*j,true);
		if(arraytemp[2]==1) result.set(4*j+1,true);
		if(arraytemp[1]==1) result.set(4*j+2,true);
		if(arraytemp[0]==1) result.set(4*j+3,true);
		j++;
		i--;
		//cout<< "check2 i=" <<i<< " j = "<<j << endl;
		
		}
	}
//cout << "result ="<<result.to_string()<<"\n";
translator temp1 = translator(result);
//cout <<"strN "<< temp1.getHexstring()<<endl;

return result;
}



/*
int main(int argc, char **argv){

bitstring b1 =bitstring((size_t) 32,33);
translator t1,t2;
 *t1=translator(b1);
cout <<"checkpoint\n";
t1.valuetosha();

cout <<"t2\n";

//char *cs = ((string) "A").c_str();
//char ch[4] = "ABC";

string test ="EFFFFFFF";




char ari[128]={'A','F','F'};
t2=translator(test);
t1=translator(b1);
}
*/


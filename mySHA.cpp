#include <fstream>
#include <iostream>
//#include <ifstream>
#include <sstream>
//#include <stream>
#include "bitstring.h"
#include "translator.h"
#include "sha1.h"
#include "MySHA.h"

HashSHA::HashSHA(){
}



void HashSHA::hashFoo(bitstring b){
char c;
char * pEnd;
trl = translator(b);
hexstring = trl.getHexstring();
char *ch = (char*) hexstring.c_str();

long int li;
int aa=0;


ofstream outbin( ".binary.bin", ios::binary );
while(aa<(int)hexstring.size()){
	char letra[2];
 	letra[0] = ch[aa];
	//if (ch[aa+1] == '\0') cout <<"erroE \n"; //TODO 
 	letra[1] = ch[aa+1];
	li = strtol((const char*)letra,&pEnd,16); // dividir a string em pares, ir escrevendo no file sequencialmente. // 0xDEADBEEF;
  	outbin.write(reinterpret_cast <const char*> (&li), 1);
	aa=aa+2;
	}
outbin.close();
FILE *	fp = fopen(".binary.bin","rb");
	
	/*
         *  Reset the SHA1 object and process input
         */
        sha.Reset();

        c = fgetc(fp);
        while(!feof(fp))
        {
            sha.Input(c);
            c = fgetc(fp);
        }
        fclose(fp);
	
	if(!sha.Result(message_digest)){cout << "Error: digest not done"<< endl;}
	else{
	//cout << "sha success!\n";
        }

remove(".binary.bin"); // remover o ficheiro .binary.bin

}



bitstring HashSHA::getDigest(){
string str;
bitstring out;
translator t;
        
stringstream ss (stringstream::in | stringstream::out);

	ss << std::hex << message_digest[0];
	ss << std::hex << message_digest[1];
	ss << std::hex << message_digest[2];
	ss << std::hex << message_digest[3];
	ss << std::hex << message_digest[4];
	ss>> str;

for(int ii=0;ii<(int)str.size();ii++) str[ii]=toupper(str[ii]);

t=translator((string) str);
out=t.getBitstring();

//t->translator::~translator();
//cout <<"\nDIGEST = "<<str<< " \n";
return out;
}












/*
int main(int argc, char *argv[]){
SHA1 sha;

//FILE        *fp;                        // File pointer for reading files
//char        c;                          // Character read from file
//unsigned    message_digest[5];          // Message digest from "sha"
//int         i;                          // Counter
//bool        reading_stdin;              // Are we reading standard in?
//bool        read_stdin = false;         // Have we read stdin?

bitstring b= bitstring((size_t) 32,3735928559);
 *
translator t= translator(b);

string x = t.getHexstring();

char *ch = (char*) x.c_str();

char * pEnd;
cout << "checkpoint long int convertion\n";



ofstream outbin( ".binary.bin", ios::binary );
long int li;
int aa=0;
while(ch[aa]!='\0'){
char letra[2];
 letra[0] = ch[aa];
if (ch[aa+1] == '\0') cout <<"erroE \n"; //TODO fix it fix it (exception)
 letra[1] = ch[aa+1];
cout << "checkpoint "<<letra<<" long int convertion\n";
// TODO dividir a string em pares de 2, ir escrevendo no file sequencialmente.
li = strtol((const char*)letra,&pEnd,16);
// 0xDEADBEEF;
//cout << "checkpoint long int convertion\n";
//File operation binary
  //outbin.write(reinterpret_cast <const char*> (0xDEADBEEF),32);
  outbin.write(reinterpret_cast <const char*> (&li), 1);
  //outbin.write(reinterpret_cast <const char*> (&li), 4);
aa=aa+2;
}
outbin.close();


	// *************************************

	fp = fopen(".binary.bin","rb");
	// *
         *  Reset the SHA1 object and process input
         // *
        sha.Reset();

        c = fgetc(fp);
        while(!feof(fp))
        {
            sha.Input(c);
            c = fgetc(fp);
        }

        if (!reading_stdin)
        {
            fclose(fp);
        }

        if (!sha.Result(message_digest))
        {
            fprintf(stderr,"sha: could not compute message digest for %s\n",
                    reading_stdin?"STDIN":"dragons");
        }
        else
        {
            printf( "%08X %08X %08X %08X %08X - %s\n",
                    message_digest[0],
                    message_digest[1],
                    message_digest[2],
                    message_digest[3],
                    message_digest[4],
                    reading_stdin?"STDIN":"dragons");


stringstream ss (stringstream::in | stringstream::out);

string x;        
ss << hex << message_digest[0];
ss << hex << message_digest[1];
ss << hex << message_digest[2];
ss << hex << message_digest[3];
ss << hex << message_digest[4];
ss>> x;

for(int i=0;i<x.size();i++) x[i]=toupper(x[i]);

cout <<x<< endl;

}



HashSHA gg;

gg=HashSHA();
bitstring xx;
bitstring xy;
xx=bitstring((size_t) 32,3735928559);
gg.hashFoo(xx);
xx=gg.getDigest();



}*/

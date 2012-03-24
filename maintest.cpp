int main(){


cout << "ping!!! "<<  argv[1] << "\n ";

int i=0;
bitstring bitres,bitstr0,bitstr1;

bitstring res[16];

while( i<16){
res[i]= bitstring((size_t) 4, (long) i);
//bitstr1 = bitstring((size_t) 4,(long unsigned)argv[1]);
//bitstr0=bitstr0 + 1;
//bitstr0 <<=10;
//bitres = bitstr0;
//bitres ^= bitstr1;
//bitres = xor(bitstr0,bitstr1);
cout << "number " << bitstr0.to_string() << "\n" << res[i].to_ulong() <<"\narray["<<i<<"]= "<<(res[i]).to_string()<< "\n\n";

i++;
}

/*bitres = (res[15]);
cout << (bitres).to_string() <<"\n";

bitstr1 = (res[7]);
cout << (bitstr1).to_string() <<"\n";

cout << (xorFoo(bitres,bitstr1)).to_string() <<"\n\n\n\n\n";

//cout << vTwo(12)<<"\n";*/
return 0;


}

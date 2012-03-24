bitstring xorFooX(bitstring a, bitstring b,int outsize1){

size_t asize,bsize,rightsize,outsize;
int ressize;
asize = a.size();
bsize = b.size();
outsize =(size_t) outsize1;
if((asize==bsize) && asize>= outsize) rightsize=asize;//return a^=b;

if(asize > bsize){ 
	ressize=bsize;
	if(outsize >= asize) rightsize=outsize;
	if(asize > outsize) rightsize = asize;
	}
if(bsize >= asize){
	ressize=asize;
	if(outsize >= bsize) rightsize=outsize;
	if(bsize > outsize) rightsize= bsize;
	}
//cout <<"\n        a  = "<< a.size()<<"\n";
//cout <<"        b  = "<< b.size()<<"\n";
//cout <<"  outsize  = "<< outsize<<"\n";
//cout <<" rightsize = "<<rightsize<<"\n";

bitstring aa =bitstring((size_t) a.size());
bitstring bb =bitstring((size_t) b.size());
aa.reset();
bb.reset();


	aa= a.subbits(0,a.size());
	bb= b.subbits(0,b.size());
/*
for(int i=0;i<(int)asize;i++){
	aa.set(i,a.get(i));
	
}*/

/*for(int j=0;j<(int)bsize;j++){
	bb.set(j,b.get(j));
}*/

aa^=bb;

return aa;
}




// SHA-1 here 
bitstring hashFoo1(bitstring key,bitstring b){

HashSHA gg;
bitstring xx;
bitstring xy;

	xy=myXOR(key,b,0);

	gg=HashSHA();
	gg.hashFoo(xy);

	xx=gg.getDigest();
	
return xx;
} 


/*
bitstring Mask::hashFoo(bitstring key,bitstring b){
cout << "hashFoo(...) "<< endl;

/ *	
 * HASH vai ter 256bits no minimo.
 *
 *
 * Fazer hash bruta de objectos bitstring 
 * converter o resultado de bytes para HEXA_STRING
 * fazer o print.
 * /
	
bitstring xxx=b;

//cout <<" b to String "<< b.to_string() <<endl;
//cout <<" b size "<< b.size() <<endl;

bitstring res=hashBitstring(xxx);

return res;
} 
*/


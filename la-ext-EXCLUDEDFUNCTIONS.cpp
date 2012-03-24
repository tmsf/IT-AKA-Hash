vector<bitstring > LookAheadExtractor::extractBAK(bitstring w, bitstring x) {


	cout <<"LookAheadExtractor ::w.size() =" << w.size()<<"n = "<< n <<endl;
	cout <<"LookAheadExtractor ::x.size() =" << x.size()<<"d = "<< d <<endl;
	if (w.size() != (size_t)n) {
		throw invalid_argument("LookAheadExtractor::W has wrong size");
	}
/*	if (x.size() != (size_t)d) { // if (x.size() != (size_t)d) {
		throw invalid_argument("LookAheadExtractor::X has wrong size");
	}
*/
	
	//int nw = n, kw = k, nq = d - l;	
	
	//Extractor extw(NW, KQ , DW, LW, 0), extq(NQ, KQ, DQ, LQ, 0); // 2 * l * t


	/*
	 * criar uma Mask com tamanhos necessarios para extq e extw
	 * 
	 *
	 */
	cout <<"here goes the substitute of the extractor (LookAheadExtractor.cpp line 61)\n";
	//extq=Mask(NW,DW,LW,);
	//extq=Mask(NQ,DQ,LQ,);

	srand(time(0));
	int delta =(int) rand()%15;
	vector<bitstring > result;


	
	bitstring q = x.subbits(256); //TODO GENERALIZAR O 256
	bitstring si = x.subbits(0, 256); //TODO IDEM.
	
		
	
	Mask msk_w = Mask(256,w,si,12);// TODO idem
	msk_w.creat_mask();
	vector<bitstring> extw_S = msk_w.S; // TODO vector needed. needs to be sent as an argument.
	
	bitstring ri= msk_w.extract();
	cout << "ext_Q size "<<q.size()<<endl;
	Mask msk_q = Mask(256,q,ri,12); 
// TODO idem + falta adicionar o X a funcao.
	msk_q.creat_mask();
	vector<bitstring> extq_S = msk_q.S; // TODO this vector is needed before the cicle. NEEDS TO BE SENT AS ARGUMENT
	
	
	result.push_back(ri);	 

	
	Mask temp_extq;
	Mask temp_extw;
	bitstring sit;
	bitstring rit;
	for (int i = 2; i <= t; ++i) {
		//cout<< "INTERACTION nº:"<<i <<endl;//" si = extq.extract(q, ri);\n";
		//cout<< "                        ri = extw.extract(w, si);\n";
		
		temp_extq = Mask(256,q,ri,extq_S,12);
		
		si= temp_extq.extract();//TODO o extract recebe argumentos mas n os usa. mudar isso.
		sit = bitstring(si);
		temp_extw = Mask(256,w,sit,extw_S,12);
		
		ri=msk_w.extract();
		rit=ri.subbits(0,ri.size());
		result.push_back(rit);
		
	}
	
	//cout <<"lookahead::extract result =" << (result.first).to_string()<<endl; 
	return result;
}


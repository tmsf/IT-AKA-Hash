	CC	= g++
	OPT	= -O3 -fprefetch-loop-arrays -fno-strict-aliasing #-fexpensive-optimizations
	CFLAGS	= $(OPT) -I/Users/tiago/nacl-20100830/build/nibbler/include/amd64  -I/Users/tiago/sw/include 

all: itaka

Composition: bitstring.o translator.o Composition.o
	$(CC) $(CFLAGS) bitstring.o translator.o Composition.o -o Composition -L/Users/tiago/sw/lib -lntl  -L/Users/tiago/Dropbox/tese/dodis-IT-AKA/dev/IT-AKA-Hash/ -lnacl -lm

temptranslator: bitstring.o translator.o
	$(CC) $(CFLAGS) bitstring.o translator.o -o translatorFoo 

tempHash: sha1.o bitstring.o translator.o mySHA.o Composition.o
	$(CC) $(CFLAGS) sha1.o bitstring.o translator.o mySHA.o Composition.o -o foomyhash -L/Users/tiago/sw/lib -lntl  -L/Users/tiago/Dropbox/tese/dodis-IT-AKA/dev/IT-AKA-Hash/ -lnacl  -lm

itaka: bitstring.o TheoreticAKA.o Extractor.o LookAheadExtractor.o LookAheadMAC.o  translator.o sha1.o mySHA.o Composition.o IT-AKA.o 
	$(CC) $(CFLAGS) bitstring.o  TheoreticAKA.o Extractor.o LookAheadExtractor.o LookAheadMAC.o translator.o sha1.o mySHA.o Composition.o IT-AKA.o -o itakafoo -L/Users/tiago/sw/lib -lntl  -L/Users/tiago/Dropbox/tese/dodis-IT-AKA/dev/IT-AKA-Hash/ -lnacl -lm

temp: bitstring.o TheoreticAKA.o  LookAheadExtractor.o LookAheadMAC.o  translator.o Composition.o  
		$(CC) $(CFLAGS) bitstring.o  TheoreticAKA.o LookAheadExtractor.o LookAheadMAC.o translator.o  Composition.o  -o tempFoo -L/Users/tiago/sw/lib -lntl  -L/Users/tiago/Dropbox/tese/dodis-IT-AKA/dev/IT-AKA-Hash/ -lnacl -lm


tempLA: bitstring.o  LookAheadExtractor.o LookAheadMAC.o  translator.o Composition.o  
		$(CC) $(CFLAGS) bitstring.o   LookAheadExtractor.o LookAheadMAC.o translator.o  Composition.o  -o tempLaFoo -L/Users/tiago/sw/lib -lntl  -L/Users/tiago/Dropbox/tese/dodis-IT-AKA/dev/IT-AKA-Hash/ -lnacl -lm
	
mac: bitstring.o  LookAheadMAC.o    
		$(CC) $(CFLAGS) bitstring.o    LookAheadMAC.o   -o mac -L/Users/tiago/sw/lib -lntl  -L/Users/tiago/Dropbox/tese/dodis-IT-AKA/dev/IT-AKA-Hash/ -lnacl -lm

bitstring.o: bitstring.cpp
			g++ $(OPT) -Wall -c -o bitstring.o bitstring.cpp
			
TheoreticAKA.o: TheoreticAKA.cpp
			g++ $(OPT) -Wall -c -o TheoreticAKA.o TheoreticAKA.cpp

Extractor.o:
			g++ $(OPT) -Wall -c -o Extractor.o Extractor.cpp

LookAheadExtractor.o:
			g++ $(OPT) -Wall -c -o LookAheadExtractor.o LookAheadExtractor.cpp

LookAheadMAC.o:
			g++ $(OPT) -Wall -c -o LookAheadMAC.o LookAheadMAC.cpp

IT-AKA.o:
			g++ $(OPT) -Wall -c -o IT-AKA.o IT-AKA.cpp
			
Composition.o: bitstring.o 
			g++ -O0 -Wall -c -o Composition.o Composition.cpp

mySHA.o:
			g++ -Wall -c -o mySHA.o mySHA.cpp

translator.o:
			g++  $(OPT) -Wall -c -o translator.o translator.cpp
	
clean: 
			rm -r *.o


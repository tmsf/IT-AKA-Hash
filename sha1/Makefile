	CC	= g++
	CFLAGS	= -I/Users/tiago/sw/include 

all: crash

crash: bitstring.o translator.o sha1.o crashme.o
	$(CC) $(CFLAGS) bitstring.o translator.o crashme.o sha1.o -o crashFoo 

temptranslator: bitstring.o translator.o
	$(CC) $(CFLAGS) bitstring.o translator.o -o translatorFoo 

tempHash: bitstring.o MyHash.o
	$(CC) $(CFLAGS) bitstring.o MyHash.o -o foomyhash -L/Users/tiago/sw/lib -lntl  -lm

itaka: bitstring.o TheoreticAKA.o Extractor.o LookAheadExtractor.o LookAheadMAC.o MyHash.o IT-AKA.o 
	$(CC) $(CFLAGS) bitstring.o  TheoreticAKA.o Extractor.o LookAheadExtractor.o LookAheadMAC.o MyHash.o IT-AKA.o -o itakafoo -L/Users/tiago/sw/lib -lntl  -lm
	
bitstring.o: bitstring.cpp
			g++ -Wall -c -o bitstring.o bitstring.cpp
			
TheoreticAKA.o: TheoreticAKA.cpp
			g++ -Wall -c -o TheoreticAKA.o TheoreticAKA.cpp

Extractor.o:
			g++ -Wall -c -o Extractor.o Extractor.cpp

LookAheadExtractor.o:
			g++ -Wall -c -o LookAheadExtractor.o LookAheadExtractor.cpp

LookAheadMAC.o:
			g++ -Wall -c -o LookAheadMAC.o LookAheadMAC.cpp

IT-AKA.o:
			g++ -Wall -c -o IT-AKA.o IT-AKA.cpp
			
MyHash.o: bitstring.o crashme.o
			g++ -Wall -c -o MyHash.o MyHash.cpp

crashme.o:
			g++ -Wall -c -o crashme.o crashme.cpp

clean: 
			rm -r *.o


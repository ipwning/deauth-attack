all: deauth-attack

deauth-attack: main.o deauth-attack.o
	g++ -o deauth-attack main.o deauth-attack.o -lpcap

main.o: main.cpp deauth-attack.h header.h

deauth-attack.o: deauth-attack.cpp deauth-attack.h header.h

clean:
	rm -f deauth-attack
	rm -f *.o


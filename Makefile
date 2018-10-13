# Copyright © 2018 James Sung. All rights reserved.

all: arp_spoof

arp_spoof: main.o functions.o
	g++ -g -o arp_spoof main.o functions.o -lpcap -lpthread

main.o: functions.h main.cpp
	g++ -c -g -o main.o main.cpp

functions.o: functions.h functions.cpp
	g++ -c -g -o functions.o functions.cpp

clean:
	rm -f *.o
	rm -f arp_spoof


all : mms_parser

mms_parser: main.o
	gcc -g -o mms_parser main.o -lpcap

main.o:
	gcc -g -c -o main.o main.c

clean:
	rm -rf mms_parser
	rm -f *.o


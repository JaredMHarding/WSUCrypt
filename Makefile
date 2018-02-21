CFLAGS=-c -std=c99 -Wall -pedantic

wsucrypt: wsucrypt.o
	gcc -g wsucrypt.o -o wsucrypt

wsucrypt.o: wsucrypt.c
	gcc $(CFLAGS) wsucrypt.c

clean:
	rm -f wsucrypt *.exe *.o
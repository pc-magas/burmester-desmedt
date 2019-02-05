CC=mpicc

buildsDir: ./builds
	mkdir ./builds

main: ./builds message dh main.c 
	$(CC) -o ./builds/main main.c ./builds/dh.o ./builds/message.o  -g -lcrypto -lssl

dh: ./builds dh.c dh.h
	$(CC) -c -o ./builds/dh.o dh.c -g -lcrypto -lssl

message: message.c message.h
	$(CC) -c -o ./builds/message.o -g ./message.c

run: main
	mpirun -quiet -np 3 xterm -hold -e ./builds/main &

debug: main
	mpirun -quiet -np 3 xterm -e gdb ./builds/main

.PHONY: clean

clean:
	rm -rf ./builds && mkdir ./builds
CC=mpicc

buildsDir: ./builds
	mkdir ./builds

main: ./builds dh main.c 
	$(CC) -o ./builds/main main.c ./builds/dh.o -lcrypto -lssl

dh: ./builds dh.c dh.h
	$(CC) -c -o ./builds/dh.o dh.c -lcrypto -lssl

run: main
	mpirun -np 3 ./builds/main

.PHONY: clean

clean:
	rm -rf ./builds && mkdir ./builds
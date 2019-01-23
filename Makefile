CC=mpicc

builds: ./builds
	mkdir ./builds

main: builds main.c
	$(CC) -o ./builds/main main.c -lcrypto -lssl

run: main
	mpirun -np 3 ./builds/main

.PHONY: clean

clean:
	rm -rf ./builds && mkdir ./builds
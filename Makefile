CC=mpicc


.PHONY: buildsDir

buildsDir:
	mkdir -p ${CURDIR}/builds

main: message dh main.c 
	$(CC) -o ${CURDIR}/builds/main main.c ${CURDIR}/builds/dh.o ${CURDIR}/builds/message.o  -g -lcrypto -lssl

dh: buildsDir dh.c dh.h
	$(CC) -c -o ${CURDIR}/builds/dh.o dh.c -g -lcrypto -lssl

message: buildsDir message.c message.h
	$(CC) -c -o ${CURDIR}/builds/message.o -g ./message.c

run: main
	mpirun -quiet -np 3 xterm -hold -e ${CURDIR}/builds/main &

debug: main
	mpirun -quiet -np 3 xterm -e gdb ${CURDIR}/builds/main

.PHONY: clean

clean:
	rm -rf ${CURDIR}/builds
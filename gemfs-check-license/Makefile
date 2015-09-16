check-license: uuid.o md5.o enc-dec.o check-license.o
	gcc -o check-license test-main.c uuid.o md5.o enc-dec.o \
	       check-license.o -lssl -fPIC

uuid.o: uuid.c
	gcc -c uuid.c
md5.o: md5.c
	gcc -c md5.c
enc-dec.o: enc-dec.c
	gcc -c enc-dec.c
check-license.o: check-license.c
	gcc -c check-license.c 
libchecklic.a: 
	ar rcs libchecklic.a uuid.o md5.o check-license.o

clean: 
	rm -f check-license.o main.o uuid.o \
		enc-dec.o md5.o check-license

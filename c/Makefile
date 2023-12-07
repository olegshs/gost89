all:
	c++ -O2 -static gost_file.cpp gost89.c -o gost_file
	gcc -std=c99 -O2 gost_test.c gost89.c -o gost_test

clean:
	rm -f gost_file gost_file.exe gost_test gost_test.exe

CFLAGS=-fPIC -O0 -g -I.
OBJ=addr_map.o dwarf_eval.o ghost.o patch.o variables.o


all: libpatch.so e9afl

libpatch.so: $(OBJ)
	gcc -shared $(CFLAGS) -o $@ $^ -ldw
	./e9compile.sh patch_hook.c

e9afl:
	g++ -std=c++11 -fPIC -shared -o e9AFLPlugin.so -O2 e9AFLPlugin.cpp -I ../thirdparty/e9patch/src/e9tool/
	./e9compile.sh afl-rt.c
	./e9compile.sh afl_mark.c
	g++ -std=c++11 -fPIC -pie -O2 -o e9afl e9afl.cpp

addr_map.o: addr_map.c addr_map.h
	gcc $(CFLAGS) -c -o $@ addr_map.c

dwarf_eval.o: dwarf_eval.c dwarf_eval.h
	gcc $(CFLAGS) -c -o $@ dwarf_eval.c

ghost.o: ghost.c ghost.h
	gcc $(CFLAGS) -c -o $@ ghost.c

patch.o: patch.c patch.h
	gcc $(CFLAGS) -c -o $@ patch.c

variables.o: variables.c variables.h
	gcc $(CFLAGS) -c -o $@ variables.c

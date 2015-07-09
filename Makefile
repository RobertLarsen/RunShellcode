.phony: run clean

run_shellcode: run_shellcode.c

run: run_shellcode
	./run_shellcode 8899

clean:
	rm -f run_shellcode

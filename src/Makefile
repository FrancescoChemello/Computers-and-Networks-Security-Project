# Francesco Chemello	2121346
# Computers and Networks Security Project

# Makefile for the projects

CC = gcc

main: main.c server/server.c http_parser/http_parser.c ahocorasick/ahocorasick.c
	${CC} -O3 $^ -o main

clean:
	rm -f main
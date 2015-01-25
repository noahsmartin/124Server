all: server

server: server.cc
	g++ -std=c++0x -Wall -g server.cc -o httpd 

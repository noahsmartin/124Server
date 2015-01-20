all: server

server: server.cc
	g++ server.cc -o httpd

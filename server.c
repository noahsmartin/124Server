#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>


#define SERVICE "4587"
#define BUFFSIZE 1024
#define URILENGTH 2048


void* get_addr(struct sockaddr *sa) {
    if(sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

void errorResponse(int new_fd, int error) {
    printf("Responding with an error: %d\n", error);
}

int isNewline(unsigned char c) {
    return (c == '\n' || c == '\r');
}

int isWhitespace(unsigned char c) {
    return (c == ' ' || c == '\t');
}

int removeCarriageReturn(unsigned char* source, unsigned char* destination, int maxLength) {
    memset(destination, 0, BUFFSIZE);
    int length = 0;
    int i = 0;
    for(i = 0; i < maxLength; i++) {
        if(source[i] != '\r') {
            destination[length] = source[i];
            length++;
        }
    }
    return length;
}

void handleConnection(int new_fd) {
    unsigned char* rec = (unsigned char*) malloc(BUFFSIZE);
    unsigned char* buff = (unsigned char*) malloc(BUFFSIZE);
    memset(rec, 0, BUFFSIZE);
    int len;
    int newline = 0;

    char methodString[] = "GET";
    char versionString[] = "HTTP/";
    int lineNum = 0;
    int hasMethod = 0, hasResource = 0;
    int methodLength = 0, versionLength = 0;
    char resource[URILENGTH];  // This will hold the URI resource
    int resourceLength = 0;
    char version[3];
    int versionStringLength = 0;

    int linePosition = 0;
    int lineHasSeparator = 0;

    memset(resource, 0, URILENGTH);
    memset(version, 0, 3);

    for( ;(len = recv(new_fd, buff, BUFFSIZE, 0)) > 0; memset(buff, 0, BUFFSIZE)) {
        int position = 0;
        printf("Received: %s\n", buff);
        len = removeCarriageReturn(buff, rec, len);
        if(len < 1) {
            continue;
        }

        if(lineNum == 0) {
            // This is where the first line is processed
            if(!hasMethod) {
                for(; methodLength < 3 && position < len; methodLength++, position++) {
                    if(methodString[methodLength] != rec[position]) {
                        free(rec);
                        free(buff);
                        errorResponse(new_fd, 400);
                        return;
                    }
                }
                if(methodLength == 3) {
                    hasMethod = 1;
                }
                if(position == len) {
                    // We need to wait for more data
                    continue;
                }
            }
            if(!hasResource) {
                while(resourceLength == 0 && position < len && isWhitespace(rec[position])) {
                    position++;
                }
                while(position < len && !isWhitespace(rec[position])) {
                    if(isNewline(rec[position])) {
                        // We don't expect a newline before the HTTP version
                        free(rec);
                        free(buff);
                        errorResponse(new_fd, 400);
                        return;
                    } else {
                        if(resourceLength > URILENGTH) {
                            // We can't handle a resource requested longer than URILENGTH
                            free(rec);
                            free(buff);
                            errorResponse(new_fd, 500);
                            return;
                        }
                        resource[resourceLength] = rec[position];
                        position++;
                        resourceLength++;
                    }
                }
                if(position == len) {
                    // We need to wait for more data
                    continue;
                }
                if(isWhitespace(rec[position])) {
                    printf("got the resouce %s\n", resource);
                    hasResource = 1;
                }
            }
            // Process the HTTP version
            while(versionStringLength == 0 && position < len && isWhitespace(rec[position])) {
    		    position++;
    		}
    		for(; versionStringLength < 5 && position < len; versionStringLength++, position++) {
    			if(versionString[versionStringLength] != rec[position]) {
    				free(rec);
    				free(buff);
    				errorResponse(new_fd, 400);
    				return;
    			}
    		}
		    while(!isNewline(rec[position]) && position < len) {
	    		if(versionLength > 3) {
	    			// Version shouldn't be longer than 3.
	    			free(rec);
	    			free(buff);
                    errorResponse(new_fd, 400);
	    		    return;
	    		}
	    		version[versionLength] = rec[position];
	    		position++;
	    		versionLength++;
    	    }
    	    if(position == len) {
    	    	// Wait for more data.
    	    	continue;
    	    }
    		if(isNewline(rec[position])) {
    			if(!strcmp(version, "1.0") && !strcmp(version, "1.1")) {
    				free(rec);
    				free(buff);
    				errorResponse(new_fd, 400);
    				return;
    			}
    			printf("Got the version: %s\n", version);
    			lineNum = 1;
    			position++;
    		}
        }
	    if(lineNum > 0) {
	    	int stop = 0;
	    	for(; position < len; position++) {
	    		unsigned char c = rec[position];
	        	if(linePosition == 0 && isNewline(c)) {
	        	    // Request is finished.
	        	    stop = 1;
	        	    break;
	        	}
	        	if(linePosition == 0) {
	        		if(isWhitespace(c)) {
	        			linePosition++;
	        			continue;
	        		} else {
	        			lineHasSeparator = 0;
	        		}
	        	}
	        	if(c == ':') {
	        		if(lineHasSeparator) {
		        		// We don't expect multiple colons in one header.
		        		free(rec);
	    				free(buff);
	    				errorResponse(new_fd, 400);
	    				return;
    			    } else {
    			    	lineHasSeparator = 1;
    			    }
	        	}
	        	if(isNewline(c)) {
	        		linePosition = 0;
	        		lineNum++;
	        	} else {
	        		linePosition++;
	        	}
	        }
	        if(stop) {
	        	break;
	        }
	    }
    }
    free(rec);
    free(buff);
    close(new_fd);
}

int main(int argc, char* argv[]) {
	int sock_fd, new_fd;
	socklen_t addr_size = sizeof(struct sockaddr_storage);
	struct  addrinfo hints, *res, *p;
	struct sockaddr_storage their_addr;
	int result;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;


	if ((result = getaddrinfo(NULL, SERVICE, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        return 1;
    }

    for(p = res; p != NULL; p = p->ai_next) {
        if((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            // Lock for another
            continue;
        }

        printf("We got this socket: %d\n", sock_fd);

        int allow = 1;
        if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &allow, sizeof(int)) == -1) {
        	perror("couldnt setsockopt");
        	exit(1);
        }

        if(bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            // Try another
        	close(sock_fd);
        	continue;
        }
        break;
    }
    freeaddrinfo(res);


    if(listen(sock_fd, 10) == -1) {
    	perror("couldn't listen");
    	exit(1);
    }

    while(1) {
    	new_fd = accept(sock_fd, (struct sockaddr *)&their_addr, &addr_size);
    	if(new_fd == -1) {
    		// Something went wrong, we couldn't connect to the client
    		continue;
    	}

    	inet_ntop(their_addr.ss_family, get_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if(fork() == 0) {
            handleConnection(new_fd);
        }

        close(new_fd);
    }
    return 0;
}

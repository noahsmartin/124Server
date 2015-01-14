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
#include <string>

#define SERVICE "4587"
#define BUFFSIZE 1024
#define URILENGTH 2048


void* get_addr(struct sockaddr *sa) {
    if(sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

char* formatHeader(const char* version, int error) {
    char* buffer = (char*) malloc(15);
    bzero(buffer, 15);
    sprintf(buffer, "HTTP/%s %d ", version, error);
    char* response;
    if(error == 400) {
        response = strcat(buffer, "Bad Request\n");
    } else if(error == 404) {
        response = strcat(buffer, "Not Found\n");
    } else if(error == 200) {
        response = strcat(buffer, "OK\n");
    }
    free(buffer);
    return buffer;
}

void sendResponse(int new_fd, const char* response) {
    int length = strlen(response);
    int sentLength = 0;
    while(length != sentLength) {
        int thisTransfer = send(new_fd, response, length - sentLength, 0);
        if(thisTransfer < 0) {
            perror("Could not send");
            close(new_fd);
            return;
        }
        response = &response[thisTransfer];
        sentLength += thisTransfer;
    }
}

void errorResponse(int new_fd, int error) {
    char* response = formatHeader("1.1", error);
    sendResponse(new_fd, response);
    close(new_fd);
}

void prepareResponse(int new_fd, const char* uri, char* version) {
    if(strcmp(uri, "/") == 0) {
        uri = "/index.html";
    }
    std::string uriString = uri;
    if(uri[0] == '/') {
        std::string location = "root";
        location.append(uriString);
        uriString = location;
    }
    uri = (char*) uriString.c_str();
    printf("Going to respond %s, %s\n", version, uri);
    if(access(uri, F_OK) == 0) {
        FILE *file = fopen(uri, "r");
        if(!file) {
            char* responseHeader = formatHeader("1.1", 403);
            sendResponse(new_fd, responseHeader);
        } else {
            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            fseek(file, 0, SEEK_SET);
            unsigned char* theFile = (unsigned char*)malloc(size);
            if(theFile) {
                fread(theFile, 1, size, file);
                char* responseHeader = formatHeader("1.1", 200);
                sendResponse(new_fd, responseHeader);
                std::string contentLength = "Content-Length: ";
                contentLength.append(std::to_string(size));
                contentLength.append("\n\n");
                sendResponse(new_fd, contentLength.c_str());
                long sent = 0;
                while(sent != size) {
                    long thisSize = send(new_fd, theFile, size - sent, 0);
                    if(thisSize == -1) {
                        perror("Could not send");
                        close(new_fd);
                        return;
                    }
                    theFile = &(theFile[thisSize]);
                    sent += thisSize;
                }
            } else {
                char* responseHeader = formatHeader("1.1", 500);
                sendResponse(new_fd, responseHeader);
            }
        }
    } else {
        char* responseHeader = formatHeader("1.1", 404);
        sendResponse(new_fd, responseHeader);
    }
    close(new_fd);
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
    char resource[URILENGTH+1];  // This will hold the URI resource
    int resourceLength = 0;
    char version[4];
    int versionStringLength = 0;

    int linePosition = 0;
    int lineHasSeparator = 0;

    memset(resource, 0, URILENGTH+1);
    memset(version, 0, 4);

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
            for(; position < len; position++) {
                unsigned char c = rec[position];
                if(linePosition == 0 && isNewline(c)) {
                    // Request is finished.
                    prepareResponse(new_fd, resource, version);
                    return;
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
                    lineHasSeparator = 1;
                }
                if(isNewline(c)) {
                    linePosition = 0;
                    lineNum++;
                } else {
                    linePosition++;
                }
            }
        }
    }
    free(rec);
    free(buff);
    errorResponse(new_fd, 500);
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

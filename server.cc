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
#include <sys/stat.h>
#include <signal.h>
#include <string>
#include <libgen.h>
#include <sstream>
#include <fstream>
#include <iostream>


#define SERVICE "4587"
#define BUFFSIZE 1
#define URILENGTH 2048
#define BLOCKSIZE 1024

std::string* formatHeader(const char* version, int error) {
    char buffer[15];
    bzero(buffer, 15);
    sprintf(buffer, "HTTP/%s %d ", version, error);
    std::string* result = new std::string(buffer);
    if(error == 400) {
        result->append("Bad Request\n");
    } else if(error == 404) {
        result->append("Not Found\n");
    } else if(error == 200) {
        result->append("OK\n");
    } else if(error == 403) {
        result->append("Forbidden\n");
    }
    return result;
}

void sendResponse(int new_fd, std::string* response) {
    int length = response->length();
    int sentLength = 0;
    const char* responseArray = response->c_str();
    while(length != sentLength) {
        int thisTransfer = send(new_fd, responseArray, length - sentLength, 0);
        if(thisTransfer < 0) {
            perror("Could not send");
            close(new_fd);
            free(response);
            return;
        }
        responseArray = &responseArray[thisTransfer];
        sentLength += thisTransfer;
    }
    free(response);
}

void errorResponse(int new_fd, int error) {
    std::string* response = formatHeader("1.1", error);
    sendResponse(new_fd, response);
    std::string* contentLength = new std::string("Connection: close\n");
    sendResponse(new_fd, contentLength);
    close(new_fd);
}

int checkFileType(unsigned char *buffer, long length) {
    char jpg_start[2];
    jpg_start[0] = 0xFF;
    jpg_start[1] = 0xD8;
    char jpg_end[2];
    jpg_end[0] = 0xFF;
    jpg_end[1] = 0xD9;
    char png_sig[8];
    png_sig[0] = 0x89;
    png_sig[1] = 0x50;
    png_sig[2] = 0x4E; 
    png_sig[3] = 0x47;
    png_sig[4] = 0x0D;
    png_sig[5] = 0x0A;
    png_sig[6] = 0x1A;
    png_sig[7] = 0x0A;
    printf("\nlength: %ld\n", length);
    if(length >= 4 && memcmp(buffer, jpg_start, 2) == 0) {
            return 1; 
        }
    else if(length >= 8 && memcmp(buffer, png_sig, 8) == 0) {
            return 2;
        }
    return 0;
}

// This returns 1 if access to the directory is allowed, 0 otherwise.
int checkAccess(char * uri, struct in_addr * client_ip) {
    char s[INET6_ADDRSTRLEN];
    // check for a .htaccess
    std::string dirPath((uri));
    dirPath.append("/.htaccess");
    std::ifstream infile(dirPath.c_str());
    if(infile.fail()) {
        // reading the infile failed, ignore it and ALLOW EVERYTHINGGG
        return 1;
    }
    // parse the file
    std::string line, perm, from, rule;
    while( std::getline(infile, line)) {
        std::stringstream ss(line);
        ss >> perm;
        ss >> from;
        ss >> rule;

        // parse the rule to determine if it is an ip address or a domain
        size_t pos = rule.find_first_of("/");
        if( pos == std::string::npos) {
            printf("\nprocessing: %s\n", rule.c_str());
            // There's no slash character, treat it as a domain name rule.
            struct addrinfo hints, *res;
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET;

            // Check results 
            // TODO error handling
            if(getaddrinfo(rule.c_str(), NULL, &hints, &res) == 0) {
                // check each element of result
                while(res != NULL){
                    void* check_addr = &((struct sockaddr_in*)res->ai_addr)->sin_addr;
                    inet_ntop(res->ai_addr->sa_family, check_addr, s, sizeof s);
                    printf("\nserver: checking connection from %s (%s)\n", s, rule.c_str());

                    if(((in_addr *) check_addr)->s_addr == client_ip->s_addr) {
                        if(perm.compare("allow") == 0) {
                            return 1;
                        } else {
                            return 0;
                        }
                    }
                    res = res -> ai_next;
                }
            }
            freeaddrinfo(res);
            // if there are no entries (or addrinfo is broken... potential security hazard), 
            // it cannot possibly match, so treat the rule as pass.
        }
        else {
            // it's an ip rule. Substring it!
            std::string ip_str = rule.substr(0, pos);
            std::string bits = rule.substr(pos+1, std::string::npos);
            std::cout << ip_str;
            std::cout << bits;
            uint32_t rule_ip = inet_addr(ip_str.c_str());
            uint32_t num_bits = atoi(bits.c_str());
            uint32_t mask = 0xFFFFFFFF;
            mask = mask << (32 - num_bits);

            if((rule_ip & mask) == (client_ip->s_addr & mask)) {
                printf("%s", perm.c_str());
                if(perm.compare("allow") == 0) {
                    return 1;
                }
                else {
                    return 0;
                }         
            }  
        }
    } 
    // process one line per rule, apply from top to bottom. default to allow
     
    return 1;
}

long min(long a, long b) {
    if(a < b) {
        return a;
    }
    return b;
}

int sendData(int fd, unsigned char* buffer, int size) {
    int sent = 0;
    while(sent < size) {
        int result = send(fd, buffer, size - sent, 0);
        if(result <= 0) {
            return result;
        }
        buffer = &buffer[result];
        sent += result;
    }
    return size;
}

// This returns 0 if the connection is not finished
int prepareResponse(int new_fd, const char* root, char* uri, char* version, int isClose, struct in_addr * client_ip) {
    std::string uriString = uri;
    std::string location(root);
    int compare_length = location.length();
    if(uri[0] == '/') {
        location.append(uriString);
        struct stat st_buf = {0};
        lstat(location.c_str(), &st_buf);
        if(S_ISDIR(st_buf.st_mode)) {
            location.append("/index.html");
        }
        char* path = realpath(location.c_str(), NULL);
        std::string locCopy(location.c_str());
        char * dir = dirname((char*)locCopy.c_str());
        // check for 403 first
        if(dir != NULL && !checkAccess(dir, client_ip)) {
            errorResponse(new_fd, 403);
            return 1;
        }
        // reset the path (with errno for safety)
        errno = 0;
        path = realpath(location.c_str(), NULL);
        if(errno) {
            free(path);
            perror("Error getting real path");
            // This would happen if the file does not exist
            // TODO: determine if this should be 404 or 400
            errorResponse(new_fd, 404);
            return 1;
        }
        uriString = path;
        free(path);
        if(uriString.compare(0,compare_length, root)) {
            errorResponse(new_fd, 400);
            return 1;
        }
    } else {
        std::string* responseHeader = formatHeader("1.1", 404);
        sendResponse(new_fd, responseHeader);
        return 1;
    }
    uri = (char*) uriString.c_str();
    printf("Going to respond %s, %s\n", version, uri);

    struct stat perm_buf = {0};
    lstat(uri, &perm_buf);
    std::string uriCopy(uri);
    // check if file is world-readable
    if((perm_buf.st_mode & S_IROTH) == 0) {
        errorResponse(new_fd, 403);
        return 1;
    }
    else {
        FILE *file = fopen(uri, "r");
        if(file)
        {
            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            fseek(file, 0, SEEK_SET);
            unsigned char* theFile = (unsigned char*)malloc(BLOCKSIZE);
            if(theFile) {
                fread(theFile, 1, BLOCKSIZE, file);
                std::string* responseHeader = formatHeader("1.1", 200);
                sendResponse(new_fd, responseHeader);
                std::string* contentLength = new std::string("Content-Length: ");
                contentLength->append(std::to_string(size));
                contentLength->append("\n");
                sendResponse(new_fd, contentLength);
                std::string* contentType = new std::string("Content-Type: ");
                
                switch(checkFileType(theFile, size)) {
                    case 1:
                        contentType->append("image/jpeg");
                        break;
                    case 2:
                        contentType->append("image/png");
                        break; 
                    default:
                        contentType->append("text/html");
                        break;
                }
                contentType->append("\n");
                sendResponse(new_fd, contentType);
                if(!strcmp(version, "1.1") && isClose) {
                    std::string* contentLength = new std::string("Connection: close\n");
                    sendResponse(new_fd, contentLength);
                }
                sendResponse(new_fd, new std::string("\n"));
                long sent = 0;
                while(sent < size) {
                    if(sendData(new_fd, theFile, min(BLOCKSIZE, size-sent)) <= 0) {
                        perror("Could not send");
                        close(new_fd);
                        return 1;
                    }
                    sent += min(BLOCKSIZE, size-sent);
                    fread(theFile, 1, BLOCKSIZE, file);
                }
            } else {
                std::string* responseHeader = formatHeader("1.1", 500);
                sendResponse(new_fd, responseHeader);
            }
        }
    }
    if(strcmp(version, "1.1") || isClose) {
        close(new_fd);
        return 1;
    }
    return 0;
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

bool isDouble(char* string) {
    char* ptr = 0;
    strtod(string, &ptr);
    if(*ptr != '\0') {
        return 0;
    }
    if(ptr == string) {
        return 0;
    }
    return 1;
}

// This returns 0 if the connection is not finished.
int handleConnection(int new_fd, const char* root, struct in_addr * client_ip) {
    unsigned char* rec = (unsigned char*) malloc(BUFFSIZE);
    unsigned char* buff = (unsigned char*) malloc(BUFFSIZE);
    memset(rec, 0, BUFFSIZE);
    int len;

    char methodString[] = "GET";
    char versionString[] = "HTTP/";
    char connection[] = "Connection";
    char close[] = ": close";
    int isClose = 0;
    int isConnection = 1;
    int lineNum = 0;
    int hasMethod = 0, hasResource = 0;
    int methodLength = 0, versionLength = 0;
    char resource[URILENGTH+1];  // This will hold the URI resource
    int resourceLength = 0;
    char version[1024] = {0};
    int versionStringLength = 0;

    int linePosition = 0;
    int lineHasSeparator = 0;
    int currentLinePosition = 0;

    memset(resource, 0, URILENGTH+1);
    memset(version, 0, 4);

    for( ;(len = recv(new_fd, buff, BUFFSIZE, 0)) > 0; memset(buff, 0, BUFFSIZE)) {
        int position = 0;
       // printf("Received: %s\n", buff);
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
                        return 1;
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
                        return 1;
                    } else {
                        if(resourceLength > URILENGTH) {
                            // We can't handle a resource requested longer than URILENGTH
                            free(rec);
                            free(buff);
                            errorResponse(new_fd, 500);
                            return 1;
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
                    printf("got the resource %s\n", resource);
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
                    return 1;
                }
            }
            while(!isNewline(rec[position]) && position < len) {
                if(versionLength > 1023) {
                    // We can't handle a version longer than 1023
                    free(rec);
                    free(buff);
                    errorResponse(new_fd, 500);
                    return 1;
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
                char* dotStart = strstr(version, ".");
                if(!isDouble(version) ||
                  (dotStart == NULL || dotStart == version || dotStart == version + strlen(version) - 1)) {
                    free(rec);
                    free(buff);
                    errorResponse(new_fd, 400);
                    return 1;
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
                    return prepareResponse(new_fd, root, resource, version, isClose, client_ip);
                }
                if(linePosition == 0) {
                    if(isWhitespace(c)) {
                        linePosition++;
                        continue;
                    } else {
                        lineHasSeparator = 0;
                        currentLinePosition = 0;
                    }
                }
                if(c == ':') {
                    lineHasSeparator = 1;
                    if(isConnection && currentLinePosition == 10) {
                        isClose = 1;
                    } else {
                        isConnection = 0;
                    }
                }
                if(lineHasSeparator == 0) {
                    if(currentLinePosition > 9 || tolower(c) != tolower(connection[currentLinePosition])) {
                        isConnection = 0;
                    }
                } else {
                    if(isConnection && (currentLinePosition - 10 > 6 || c != close[currentLinePosition - 10])) {
                        if(currentLinePosition - 10 != 7 || !isNewline(c)) {
                            isClose = 0;
                        }
                    }
                }
                if(isNewline(c)) {
                    linePosition = 0;
                    isConnection = 1;
                    lineNum++;
                } else {
                    linePosition++;
                    currentLinePosition++;
                }
            }
        }
    }
    free(rec);
    free(buff);
    // If we get to this point there was a timeout
    errorResponse(new_fd, 400);
    return 1;
}

int main(int argc, char* argv[]) {
    int sock_fd, new_fd;
    socklen_t addr_size = sizeof(struct sockaddr_storage);
    struct sockaddr_in address, client_address;
    char s[INET6_ADDRSTRLEN];

    if(argc < 3) {
        printf("Usage: ./httpd [PORT] [PATH]\n");
        exit(1);
    }
    errno = 0;
    char* thepath = realpath(argv[2], NULL);
    if(errno) {
        printf("Invalid path.\n");
        exit(1);
    }
    free(thepath);

    client_address = {0};
    address = {0};

    if((sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        // Could not create socket.
        exit(1);
    }

    printf("We got this socket: %d\n", sock_fd);

    int allow = 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &allow, sizeof(int)) < 0) {
        perror("couldnt setsockopt");
        exit(1);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(atoi(argv[1]));

    if(bind(sock_fd, (struct sockaddr*) &address, sizeof(address)) < 0) {
        perror("Couldn't bind");
        close(sock_fd);
        exit(1);
    }

    if(listen(sock_fd, 128) < 0) {
        perror("couldn't listen");
        close(sock_fd);
        exit(1);
    }

    while(1) {
        new_fd = accept(sock_fd, (struct sockaddr *)&client_address, &addr_size);
        if(new_fd == -1) {
            // Something went wrong, we couldn't connect to the client
            continue;
        }

        struct in_addr * client_addr = &(client_address.sin_addr);
        inet_ntop(AF_INET, client_addr, s, sizeof s);
        printf("server: got connection from %s \n", s);

        if(fork() == 0) {
            struct timeval tv = {0};
            tv.tv_sec = 10;
            if(setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval))) {
                perror("couldn't setsockopt");
                close(new_fd);
                exit(1);
            }
            char * root_path = realpath(argv[2], NULL);
            int finished = 0;
            while(!finished) {
                finished = handleConnection(new_fd, root_path, client_addr);
            }
            free(root_path);
        } else {
            close(new_fd);
        }
    }
    return 0;
}

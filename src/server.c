// Francesco Chemello   2121346
// Computers and Networks Security Project

// Server implementation 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
// Linux libraries
#include <sys/socket.h>
#include <netinet/in.h>

// Parser header file
#include "http_parser.h"

#define PORT 8080
#define BUFFER_SIZE 4096

char* find_CRLF(char* buffer){
    char* header = NULL;
    char* temp = buffer;
    while((temp = strstr(temp, "\r\n\r\n"))){
        header = temp;
        temp += 4;
    }
    if(header){
        *header = '\0';
    }
    return buffer;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    const char* response = NULL;

    // Creation of the tree
    ACtree = create_tree();
    if (ACtree == NULL) {
        return 1; // Exit if tree creation fails
    }

    // Add patterns to the tree
    add_string(ACtree, "SELECT * FROM datatable\0");
    add_string(ACtree, "(){;}; echo /bin/ls\0");
    add_string(ACtree, "DELETE datatable\0");
    add_string(ACtree, "DROP TABLE database\0");

    // Socket creation
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Socket configuration
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("HTTP server listening on port %d...\n", PORT);

    // Main loop to accept and handle requests
    while (1) {
       
        // Accept a new connection
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept failed");
            continue;
        }

        memset(buffer, 0, BUFFER_SIZE);
        read(new_socket, buffer, BUFFER_SIZE - 1);

        printf("---- REQUEST ----\n%s\n------------------\n", buffer);

        bool malicious = false; // Placeholder for parser result
        
        // 1. Understand the type of request -> GET, HEADER, POST, or DELETE
        char buffer_copy[sizeof(buffer)];
        strcpy(buffer_copy, buffer); // Create a copy of the buffer
        char * method = strtok(buffer_copy, " ");
        if(method == NULL) {
            perror("Failed to parse request method");
            close(new_socket);
            continue;
        
        }
        if(strcmp(method, "GET") == 0) {

            printf("GET method detected!\n");

            // 2. Extract the section to analize with the parser
            // I analize only the header of the request
            char* header = find_CRLF(buffer); // Extract the header part of the request
            if(header == NULL) {
                perror("Failed to parse request header");
                close(new_socket);
                continue;
            }

            printf("Parser called!\n");

            // 3. Call the parser function with the header
            malicious = header_parser(header, strlen(header)); // Call the parser function with the header

            printf("Parsing compleated!\n");

        }else{
            if(strcmp(method, "POST") == 0){

                printf("POST method detected!\n");

                // 2. Extract the section to analize with the parser
                // I analize both header and body of the request
                char* header = find_CRLF(buffer); // Extract the header part of the request
                if(header == NULL) {
                    perror("Failed to parse request header");
                    close(new_socket);
                    continue;
                }
                char body_buffer[sizeof(buffer)-strlen(header)-4];
                strcpy(body_buffer, buffer + strlen(header) + 4);
                char* body = find_CRLF(body_buffer); // Extract the body part of the request
                if(body == NULL) {
                    perror("Failed to parse request body");
                    close(new_socket);
                    continue;
                }

                printf("Parser called!\n");

                // 3. Call the parser function with the header
                malicious = header_body_parser(header, strlen(header), body, strlen(body)); // Call the parser function with the header and body
            
                printf("Parsing compleated!\n");

            }else{
                // If the request is neither GET nor POST, handle it accordingly
                printf("Unsupported request method: <%s>\n", method);
            }
        }

        // 4. If the output is true (malicious), then I refuse the connection; otherwise I send back the response
        if(malicious) {

            printf("Malicious request detected!\n");

            // If the parser detects a malicious request, send a 403 Forbidden response
            response =
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 39\r\n"
                "\r\n"
                "Forbidden: Malicious request detected!\n";
        }else{

            printf("Request is safe!\n");

            // Example response message
            response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n"
                "\r\n"
                "Hello, user!\n";
        }

        printf("Sending the response\n");

        // Send back the response
        send(new_socket, response, strlen(response), 0);
        close(new_socket);

        printf("DONE!\n");

    }

    return 0;
}

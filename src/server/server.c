// Francesco Chemello   2121346
// Computers and Networks Security Project

// Server implementation 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
// Linux libraries
#include <sys/socket.h>
#include <netinet/in.h>
// Include for select function
#include <sys/select.h>

// Parser header file
#include "server.h"

#define PORT 8080
#define BUFFER_SIZE 4096

// Function to find the end of the header in the HTTP request
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

// Function to decode URL-encoded text
char* decoding(char* text, int text_len){
    char* decoded_text = (char*)malloc(text_len + 1);
    if(decoded_text == NULL) {
        perror("Failed to allocate memory for decoded text");
        return NULL;
    }
    int j = 0;
    for(int i = 0; i < text_len; i++){
        if(text[i] == '%'){
            // Verify that there are at least two characters after '%'
            if(i + 2 < text_len && isxdigit(text[i + 1]) && isxdigit(text[i + 2])) {
                int value;
                sscanf(text + i + 1, "%2x", &value);
                decoded_text[j++] = (char)value;
                i += 2; // Skip the next two characters
            } else {
                // If the format is incorrect, just copy the '%'
                decoded_text[j++] = text[i];
            }
        } else if(text[i] == '+'){
            decoded_text[j++] = ' ';
        } else {
            decoded_text[j++] = text[i];
        }
    }
    decoded_text[j] = '\0';
    return decoded_text;
}

void server(){
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    const char* response = NULL;

    time_t start, end;

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
        // Check if the server receives the termination command
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        FD_SET(STDIN_FILENO, &readfds); // Add stdin to the set for termination command
        int maxfd = (server_fd > STDIN_FILENO) ? server_fd : STDIN_FILENO;

        printf("Press the key 'Esc' + 'Enter' to stop the server...\n");
        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char cmd[8];
            fgets(cmd, sizeof(cmd), stdin);
            // Esc is decoded as ASCII 27 '\x1b'
            if (cmd[0] == '\x1b') {
                printf("Server stopped by user command.\n");
                break; // Exit the loop to stop the server
            }
        }
       
        // A new connection is ready to be accepted
        if(FD_ISSET(server_fd, &readfds)) {
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
            if(strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0 || strcmp(method, "DELETE") == 0 || strcmp(method, "OPTIONS") == 0 || strcmp(method, "TRACE") == 0) {

                start = clock();
                
                // 2. Extract the section to analize with the parser
                // I analize only the header of the request
                char* header = find_CRLF(buffer); // Extract the header part of the request
                if(header == NULL) {
                    perror("Failed to parse request header");
                    response = "HTTP/1.1 500 Internal Server Error\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 45\r\n"
                                "\r\n"
                                "Internal Server Error: Failed to decode body\n";
                    send(new_socket, response, strlen(response), 0);
                    close(new_socket);
                    continue;
                }

                // Check if the header is encoded
                header = decoding(header, strlen(header)); // Decode the header if it is encoded
                if(header == NULL) {
                perror("Failed to parse request header");
                    response = "HTTP/1.1 500 Internal Server Error\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 45\r\n"
                                "\r\n"
                                "Internal Server Error: Failed to decode body\n";
                    send(new_socket, response, strlen(response), 0);
                    close(new_socket);
                    continue;
                }

                // 3. Call the parser function with the header
                malicious = header_parser(header, strlen(header)); // Call the parser function with the header
                
                end = clock();
                printf("Time taken to check the request: %ld milliseconds\n", (end - start)); // Print the time for checking the request

                free(header);

            }else{
                if(strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0) {

                    start = clock();

                    // 2. Extract the section to analize with the parser
                    // I analize both header and body of the request
                    char* header = find_CRLF(buffer); // Extract the header part of the request
                    if(header == NULL) {
                        perror("Failed to parse request header");
                        response = "HTTP/1.1 500 Internal Server Error\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 54\r\n"
                                "\r\n"
                                "Internal Server Error: Failed to parse request header\n";
                        send(new_socket, response, strlen(response), 0);
                        close(new_socket);
                        continue;
                    }

                    header = decoding(header, strlen(header)); // Decode the header if it is encoded
                    if(header == NULL) {
                        perror("Failed to decode header");
                        response = "HTTP/1.1 500 Internal Server Error\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 47\r\n"
                                "\r\n"
                                "Internal Server Error: Failed to decode header\n";
                        send(new_socket, response, strlen(response), 0);
                        close(new_socket);
                        continue;
                    }
                    
                    char body_buffer[sizeof(buffer)-strlen(header)-4];
                    strcpy(body_buffer, buffer + strlen(header) + 4);
                    char* body = find_CRLF(body_buffer); // Extract the body part of the request
                    if(body == NULL) {
                        perror("Failed to parse request body");
                        perror("Failed to parse request body");
                        response = "HTTP/1.1 500 Internal Server Error\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 52\r\n"
                                "\r\n"
                                "Internal Server Error: Failed to parse request body\n";
                        send(new_socket, response, strlen(response), 0);
                        close(new_socket);
                        continue;
                    }

                    body = decoding(body, strlen(body)); // Decode the body if it is encoded
                    if(body == NULL) {
                        perror("Failed to decode body");
                        response = "HTTP/1.1 500 Internal Server Error\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 45\r\n"
                                "\r\n"
                                "Internal Server Error: Failed to decode body\n";
                        send(new_socket, response, strlen(response), 0);
                        close(new_socket);
                        continue;
                    }

                    // 3. Call the parser function with the header
                    malicious = header_body_parser(header, strlen(header), body, strlen(body)); // Call the parser function with the header and body
                    end = clock();

                    printf("Time taken to check the request: %ld milliseconds\n", (end - start)); // Print the time for checking the request

                    free(header);
                    free(body);

                }else{
                    // If the request is neither GET nor POST, handle it accordingly
                    printf("Unsupported request method: <%s>\n", method);
                }
            }

            // 4. If the output is true (malicious), then I refuse the connection; otherwise I send back the response
            if(malicious) {

                // For debugging purposes
                printf("Malicious request detected!\n\n");

                // If the parser detects a malicious request, send a 403 Forbidden response
                response =
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 39\r\n"
                    "\r\n"
                    "Forbidden: Malicious request detected!\n";
            }else{

                printf("Request is safe!\n\n");

                // Example response message
                response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 13\r\n"
                    "\r\n"
                    "Hello, user!\n";
            }

            // Send back the response
            send(new_socket, response, strlen(response), 0);
            close(new_socket);
        }
    }
}

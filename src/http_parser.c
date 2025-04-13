// Francesco Chemello   2121346
// Computers and Networks Security Project

// Parser for HTTP requests

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "http_parser.h"

// Method from server.c
// char* find_CRLF(char* buffer){
//     char* header = NULL;
//     char* temp = buffer;
//     while((temp = strstr(temp, "\r\n\r\n"))){
//         header = temp;
//         temp += 4;
//     }
//     if(header){
//         *header = '\0';
//     }
//     return buffer;
// }


// Method to print the line
// For debugging purposes
// This method is not used in the final version of the code
void print_line(char* c, int len){
    for(int i = 0; i < len; i++){
        printf("%c", c[i]);
    }
}

// Method that checks if there is malicious content in the header
// This method is called if the request is a GET or HEADER request
bool header_parser(char* header, int header_len){
    int i = 0;
    int j = 0;

    bool malicious = false;

    for(j = 0; j < header_len; j++){
        char c = header[j];
        if(c == '\r'){
            // Check if the next character is a newline
            if(j + 1 < header_len && header[j + 1] == '\n'){
                // Found a CRLF -> end of an header line
                // Pass to the parser the header line

                // For debugging purposes
                // printf("Evaluation of the HEADER line: >>");
                // print_line(header + i, j - i);
                // printf("<<\n");

                bool eval = parser(header + i, j - i, ACtree);
                // Implement OR function
                malicious = malicious || eval;
                i = j + 2;
                j += 2; // Skip the newline character
            }
        }
    }

    // For debugging purposes
    // printf("Evaluation of the HEADER line: >>");
    // print_line(header + i, j - i);
    // printf("<<\n");

    bool eval = parser(header + i, j - i + 2, ACtree);
    // Implement OR function
    malicious = malicious || eval;

    return malicious;
}

// Method that checks if there is malicious content in the header and body
// This method is called only if the request is a POST request
bool header_body_parser(char* header, int header_len, char* body, int body_len){
    int i = 0;
    int j = 0;
    bool malicious = false;

    malicious = header_parser(header, header_len);
        
    for(j = 0; j < body_len; j++){
        char c = body[j];
        if(c == '\n'){

            // For debugging purposes
            // printf("Evaluation of the BODY line: >>");
            // print_line(body + i, j - i);
            // printf("<<\n");

            bool eval = parser(body + i, j - i, ACtree);
            // Implement OR function
            malicious = malicious || eval;
            i = j + 1;
            j += 1; // Skip the newline character
        }
    }

    // For debugging purposes
    // printf("Evaluation of the BODY line: >>");
    // print_line(body + i, j - i);
    // printf("<<\n");

    bool eval = parser(body + i, j - i, ACtree);
    // Implement OR function
    malicious = malicious || eval;

    return malicious;
}


// // Test main
// int main(){

//     char * header = NULL;
//     char * body = NULL;

//     ACtree = create_tree();
//     if (ACtree == NULL) {
//         return 1; // Exit if tree creation fails
//     }

//     // Add patterns to the tree
//     add_string(ACtree, "SELECT * FROM datatable\0");
//     add_string(ACtree, "(){;}; echo /bin/ls\0");
//     add_string(ACtree, "DELETE datatable\0");
//     add_string(ACtree, "DROP TABLE database\0");

//     // printf("Tree structure:\n");
//     // print_tree(ACtree); // Print the tree structure starting from the root node
//     // printf("\n");

//     char normal_GET_request[] = "GET /index.html HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n\0";
//     char normal_POST_request[] = "POST /submit HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nname=John&age=30\0";

//     char malicious_GET_request[] = "GET /index.html HTTP/1.1 (){;}; echo /bin/ls\r\nHost: localhost\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\nSELECT * FROM datatable\0";
//     char malicious_POST_request[] = "POST /submit HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nname=John&age=30; DROP TABLE database\0";

//     // Test the http parser
//     printf("---- REQUEST ----\n%s\n------------------\n", normal_GET_request);
    
//     header = find_CRLF(normal_GET_request); // Extract the header part of the request

//     // printf("My HEADER is: >>");
//     // print_line(header, strlen(header));
//     // printf("<<\n");
//     // printf("My HEADER LEN is: %d\n", strlen(header));
    
//     if(!(header_parser(header, strlen(header)))){
//         printf("\nNo match found\n"); // Print the input string
//     }else{
//         printf("\nMalicious content found!\n"); // Print the input string
//     }
//     printf("\n\n");

//     printf("---- REQUEST ----\n%s\n------------------\n", normal_POST_request);
    
//     header = find_CRLF(normal_POST_request); // Extract the header part of the request

//     // printf("My HEADER is: >>");
//     // print_line(header, strlen(header));
//     // printf("<<\n");
//     // printf("My HEADER LEN is: %d\n", strlen(header));

//     char body_buffer_1[sizeof(normal_POST_request)-strlen(header)-4];
//     strcpy(body_buffer_1, normal_POST_request + strlen(header) + 4);
//     body = find_CRLF(body_buffer_1); // Extract the body part of the request

//     // printf("My BODY is: >>");
//     // print_line(body, strlen(body));
//     // printf("<<\n");
//     // printf("My BODY LEN is: %d\n", strlen(body));
    
//     if(!(header_body_parser(header, strlen(header), body, strlen(body)))){
//         printf("\nNo match found\n"); // Print the input string
//     }else{
//         printf("\nMalicious content found!\n"); // Print the input string
//     }
//     printf("\n\n");

//     printf("---- REQUEST ----\n%s\n------------------\n", malicious_GET_request);
    
//     header = find_CRLF(malicious_GET_request); // Extract the header part of the request

//     // printf("My HEADER is: >>");
//     // print_line(header, strlen(header));
//     // printf("<<\n");
//     // printf("My HEADER LEN is: %d\n", strlen(header));
    
//     if(!(header_parser(header, strlen(header)))){
//         printf("\nNo match found\n"); // Print the input string
//     }else{
//         printf("\nMalicious content found!\n"); // Print the input string
//     }
//     printf("\n\n");

//     printf("---- REQUEST ----\n%s\n------------------\n", malicious_POST_request);
    
//     header = find_CRLF(malicious_POST_request); // Extract the header part of the request

//     // printf("My HEADER is: >>");
//     // print_line(header, strlen(header));
//     // printf("<<\n");
//     // printf("My HEADER LEN is: %d\n", strlen(header));

//     char body_buffer_2[sizeof(malicious_POST_request)-strlen(header)-4];
//     strcpy(body_buffer_2, malicious_POST_request + strlen(header) + 4);
//     body = find_CRLF(body_buffer_2); // Extract the body part of the request

//     // printf("My BODY is: >>");
//     // print_line(body, strlen(body));
//     // printf("<<\n");
//     // printf("My BODY LEN is: %d\n", strlen(body));
    
//     if(!(header_body_parser(header, strlen(header), body, strlen(body)))){
//         printf("\nNo match found\n"); // Print the input string
//     }else{
//         printf("\nMalicious content found!\n"); // Print the input string
//     }


//     printf("END\n");

//     return 0;
// }
// Francesco Chemello   2121346
// Computers and Networks Security Project

// Parser for HTTP requests

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "http_parser.h"

// Method that checks if there is malicious content in the header
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
                bool eval = parser(header + i, j - i, ACtree);

                // Implement OR function
                malicious = malicious || eval;
                i = j + 2;
                j += 2; // Skip the newline character
            }
        }
    }

    // Parse the last part of the header if it exists
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
    bool malicious_header = false;
    bool malicious_body = false;

    malicious_header = header_parser(header, header_len);

    for(j = 0; j < body_len; j++){
        char c = body[j];
        if(c == '\n'){

            // Parse the body
            bool eval = parser(body + i, j - i, ACtree);

            // Implement OR function
            malicious_body = malicious_body || eval;

            i = j + 1;
            j += 1; // Skip the newline character
        }
    }
    
    // Parse the last part of the body if it exists
    bool eval = parser(body + i, j - i, ACtree);

    // Implement OR function
    malicious_body = malicious_body || eval;

    // Implement OR function
    malicious_body = malicious_header || malicious_body;

    return malicious_body;
}
// Francesco Chemello   2121346
// Computers and Networks Security Project

// Main file

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

// Linux libraries
#include <sys/socket.h>
#include <netinet/in.h>

// Header file
#include "main.h"

// Create the Aho-Corasick tree from a file
ACtree_t * init_tree_from_file(const char *filename, ACtree_t * ACtree) {
    // Check if the tree already exists
    if(ACtree == NULL){
        ACtree = create_tree();
        // Check if the tree was created successfully
        if(ACtree == NULL){
            printf("Failed to create Aho-Corasick tree\n");
            return NULL; // Return NULL if tree creation fails
        }
    }

    char full_path[256];
    snprintf(full_path, sizeof(full_path), "ahocorasick/patterns/%s", filename); // Construct the full path

    FILE *file = fopen(full_path, "r"); // Open the file in read mode
    if(file == NULL){
        perror("Failed to open file");
        return NULL; // Return NULL if the file cannot be opened
    }

    char line[256]; // Buffer to store each line from the file
    while(fgets(line, sizeof(line), file)){ // Read each line from the file
        line[strcspn(line, "\r\n")] = 0; // Remove the newline character from the end of the line
        add_string(ACtree, line); // Add the pattern to the tree
    }

    fclose(file); // Close the file after reading all patterns
    return ACtree; // Return the created tree with patterns added
}

int main(int argc, char ** argv){
    
    // Check the line agruments
    // Is possible to add more than one file, depending on the patterns to analize
    if(argc < 2){
        printf("Usage: %s <patterns_file>\n", argv[0]);
        return 1;
    }

    ACtree = NULL;

    // Add patterns to the tree from the file patterns.txt
    for(int i = 1; i < argc; i++){
        ACtree = init_tree_from_file(argv[i], ACtree); // Create the Aho-Corasick tree from the file
        // Check if the tree was created successfully
        if (ACtree == NULL) {
            return 1; // Exit if tree creation fails
        }
    }

    // Start the server
    server();

    return 0;
}
// Francesco Chemello   2121346
// Computers and Networks Security Project

// Aho-Corasick Algorithm

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdint.h>

#include "ahocorasick.h"

typedef struct node Node_t;

// Global variable for the Aho-Corasick tree
ACtree_t* ACtree = NULL;

/**
 * Structure for a node in the tree
 * |--------------------|
 * | VALUE             |
 * | PARENT NODE        |
 * | FAIL LINK          |
 * | NUMBER OF CHILDREN |
 * | CHILDREN           |
 * |--------------------|
 * 
 * - VALUE: character value of the node
 * - PARENT NODE: link to the parent node
 * - FAIL LINK: link to the fail link
 * - NUMBER OF CHILDREN: report the number of children for that node (=0 a leaf)
 * - CHILDREN: link to an array of children
*/

struct node{
    char value;
    struct node* parent;
    struct node* fail_link;
    int num_children;
    bool end_of_string; // Flag to indicate if the node is the end of a string
    struct node** children;
};

/**
 * Structure for the tree
 * 
 * |--------------------|
 * | ROOT NODE          |
 * | NUMBER OF NODES    |
* |---------------------|
 * 
 * - ROOT NODE: link to the root node
 * - NUMBER OF NODES: number of nodes in the tree
 */
struct ACtree{
    struct node* root_node;
    int num_nodes;
};

// Create a new node for the Aho-Corasick tree
Node_t* create_node(){
    // Allocate memory for the node
    Node_t* new_node = (Node_t*)malloc(sizeof(struct node));
    if (new_node == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Initialize the node
    new_node->value = '\0'; // Initialize value to null character
    new_node->parent = NULL;
    new_node->fail_link = NULL;
    new_node->num_children = 0;
    new_node->end_of_string = false; // Initialize end_of_string to false
    new_node->children = NULL; // Initialize children to NULL

    return new_node;
}

// Method to create a new tree
ACtree_t* create_tree(){
    // Allocate memory for the tree
    ACtree_t* tree = (ACtree_t*)malloc(sizeof(struct ACtree));
    if (tree == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Initialize the tree with the root node
    tree->root_node = create_node(); // Create the root node
    ((Node_t*)tree->root_node)->value = '\0';
    ((Node_t*)tree->root_node)->fail_link = (Node_t*)tree->root_node;
    tree->num_nodes = 0; // Initialize the number of nodes to 0
    if (tree->root_node == NULL) {
        free(tree); // Free the tree if root node creation fails
        return NULL;
    }

    return tree;    
}

// Add a new node to the tree
Node_t* add_node(ACtree_t* ACtree, Node_t* parent_node, char value){
    // Search if the node is already present in the tree
    for(int i = 0; i < ((Node_t*)parent_node)->num_children; i++){
        Node_t* child = ((Node_t*)parent_node)->children[i]; // Get the child node
        if(child->value == value){
            // Node_t already exist, I return the child pointer
            return ((Node_t*)parent_node)->children[i]; // Return the child pointer
        }
    }

    
    // Create a new node
    Node_t* new_node = (Node_t*)create_node();
    
    new_node->value = value;                            // Set the value of the new node
    new_node->parent = parent_node;                     // Set the parent of the new node
    new_node->fail_link = ((ACtree_t*)ACtree)->root_node;   // I want only exact match so fail link = root
    new_node->num_children = 0;                         // Initialize the number of children to 0
    new_node->end_of_string = false;                    // Initialize end_of_string to false
    new_node->children = NULL;                          // Initialize children to NULL
    
    // Resize the array
    ((Node_t*)parent_node)->num_children += 1; // Increment the number of children of the parent node
    ((Node_t*)parent_node)->children = (Node_t**)realloc(((Node_t*)parent_node)->children, sizeof(Node_t*) * ((Node_t*)parent_node)->num_children); // Resize the array
    
    // Add the new node to the children array
    int last_index = ((Node_t*)parent_node)->num_children - 1;
    ((Node_t*)parent_node)->children[last_index] = new_node; // Assign the pointer to the new node
    
    //((Node_t*)parent_node)->num_children++; // Increment the number of children of the parent node
    
    ((ACtree_t*)ACtree)->num_nodes += 1; // Increment the number of nodes in the tree
    
    return new_node; // Return the new node
}

// Print the node (recursive function)
void print_node(Node_t* node, int depth){
    // Print the current node value with indentation based on depth
    for(int i = 0; i < depth; i++){
        printf("  "); // Indent for each level of depth
    }
    printf("%c\n", node->value); // Print the node value

    // Recursively print the children of the current node
    for(int i = 0; i < ((Node_t*)node)->num_children; i++){
        print_node(((Node_t*)node)->children[i], depth + 1); // Recursive call to print child nodes
    }
}

// Print the tree
void print_tree(ACtree_t* ACtree){
    int depth = 0;
    print_node(((ACtree_t*)ACtree)->root_node, depth); // Start printing from the root node
}

// Delete a node (recursive function)
void delete_node(Node_t* node){
    for(int i = 0; i < ((Node_t*)node)->num_children; i++){
        delete_node(*((Node_t*)node)->children + i);
    }

    free(((Node_t*)node)->children); // Free the children array
}

// Delete the tree
void delete_tree(ACtree_t* ACtree){
    if(ACtree == NULL){
        return;
    }

    // Recursively delete all the node of the tree using delete_node
    for(int i = 0; i < ((Node_t*)((ACtree_t*)ACtree)->root_node)->num_children; i++){
        delete_node(*(((ACtree_t*)ACtree)->root_node)->children + i); // Recursively delete the children
    }

    free(((ACtree_t*)ACtree)->root_node); // Free the root node
}

// Add a string to the tree
ACtree_t* add_string(ACtree_t* ACtree, char* keyword){
    // Create a new node for the root of the tree
    Node_t* parent_node = ((ACtree_t*)ACtree)->root_node; // Get the root node of the tree

    // Iterate through each character in the string
    for(int i = 0; keyword[i] != '\0'; i++){

        // Cast to lower case
        char c = tolower((unsigned char)keyword[i]); // Convert to lowercase using tolower function
        
        // Add a new node to the tree for each character in the string
        parent_node = add_node(ACtree, parent_node, c); // Add the node to the tree
    }

    ((Node_t*)parent_node)->end_of_string = true; // Set the end_of_string flag to true for the last node

    return ACtree; // Return the tree
}

// Function to print the word found (recursive function)
void match(Node_t* node){
    if(((Node_t* )node)->parent != NULL && ((Node_t*)node)->parent->value != '\0'){
        match(((Node_t*)node)->parent); // Recursive call to print the parent node
    }
    printf("%c", ((Node_t*)node)->value);
}

// Perform a single iteration in the tree
Node_t* iter(Node_t* node, char input){

    // Check if there is a child with value = input
    for(int i = 0; i < ((Node_t*)node)->num_children; i++){
        Node_t* child = ((Node_t*)node)->children[i]; // Get the child node

        // printf("Value of child %c\n", child->value); // Print the value of the child node

        if(child->value == input){

            // printf("Found, I return the child\n");

            return child; // Return the child pointer
        }
    }

    return ((Node_t*)node)->fail_link; // Return the fail link if no child found
}

// Input parser
bool parser(char* input, int len, ACtree_t* ACtree){
    bool eval = false; // Final evaluation (malicious or not)
    Node_t* current_node = ((ACtree_t*)ACtree)->root_node; // Start from the root node
    bool still_in_root = true;

    for(int i = 0; i < len; i++){
        char c = tolower((unsigned char)input[i]); // to lower case

        // iter
        current_node = iter(current_node, c);

        // Do you get root?
        if(((Node_t*)current_node)->parent == NULL){
            // Are you reading a word?
            if(isalnum((unsigned char)input[i] && ((i-1 >= 0 && isalnum((unsigned char)input[i-1])) || i == 0))){
                // You can skip the whole word
                while(i < len && isalnum((unsigned char)input[i])){
                    i++;
                    // for debug
                    c = tolower((unsigned char)input[i]);
                }
                still_in_root = true;
                continue;
            }else{
                // Do you still in root?
                if(still_in_root){
                    // Unlucky series
                    continue;
                }else{
                    // Is the character before a word?
                    if(i-1 >= 0 && isalnum((unsigned char)input[i-1])){
                        still_in_root = true;
                        continue;
                    }else{
                        // I restart from root with with this character
                        i--;
                        current_node = (Node_t*)((ACtree_t*)ACtree)->root_node;
                        still_in_root = true;
                    }
                }
            }
        }else{
            // Do you find a pattern?
            if(((Node_t*)current_node)->end_of_string){
                // Is the next character a separator?
                if(i+1 < len && !isalnum((unsigned char)input[i+1])){
                    // Print the word found
                    Node_t* opt = current_node;
                    printf("Found a match: \"");
                    match(opt); // Print the match
                    printf("\"\n");
                    // current_node = (Node_t*)((ACtree_t*)ACtree)->root_node;
                    eval = true; // Found a match
                    // still_in_root = false;
                    still_in_root = true; // Try to find a longer match
                    continue;
                }else{
                    // You are still in a word
                    // I skip the rest of the word (i.e iterate until I find a white space/separator or I finish the input)
                    while(i+1 < len && isalnum((unsigned char)input[i+1])){
                        i++;
                        // for debug
                        c = tolower((unsigned char)input[i]); // Convert to lowercase using tolower function
                    }
                    still_in_root = false;
                    continue;
                }
            }
            still_in_root = false;    
        }
    }

    return eval;
}
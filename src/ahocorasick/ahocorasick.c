// Francesco Chemello   2121346
// Computers and Networks Security Project

// Aho-Corasick Algorithm

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdint.h>

typedef struct node Node;
typedef struct ACtree Tree;


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
Node* create_node(){
    // Allocate memory for the node
    Node* new_node = (Node*)malloc(sizeof(struct node));
    if (new_node == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Initialize the node
    new_node->value = '\0'; // Initialize value to null character
    new_node->parent = NULL;
    new_node->fail_link = NULL;
    new_node->num_children = 0;
    new_node->children = NULL; // Initialize children to NULL

    return new_node;
}

// Method to create a new tree
Tree* create_tree(){
    // Allocate memory for the tree
    Tree* tree = (Tree*)malloc(sizeof(struct ACtree));
    if (tree == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Initialize the tree with the root node
    tree->root_node = create_node(); // Create the root node
    ((Node*)tree->root_node)->value = '*';
    ((Node*)tree->root_node)->fail_link = (Node*)tree->root_node;
    tree->num_nodes = 0; // Initialize the number of nodes to 0
    if (tree->root_node == NULL) {
        free(tree); // Free the tree if root node creation fails
        return NULL;
    }

    return tree;    
}

// Add a new node to the tree
Node* add_node(Tree* ACtree, Node* parent_node, char value){
    // Search if the node is already present in the tree
    for(int i = 0; i < ((Node*)parent_node)->num_children; i++){
        Node* child = ((Node*)parent_node)->children[i]; // Get the child node
        if(child->value == value){
            // Node already exist, I return the child pointer
            return ((Node*)parent_node)->children[i]; // Return the child pointer
        }
    }

    
    // Create a new node
    Node* new_node = (Node*)create_node();
    
    new_node->value = value;                            // Set the value of the new node
    new_node->parent = parent_node;                     // Set the parent of the new node
    new_node->fail_link = ((Tree*)ACtree)->root_node;   // I want only exact match so fail link = root
    new_node->num_children = 0;                         // Initialize the number of children to 0
    new_node->end_of_string = false;                    // Initialize end_of_string to false
    new_node->children = NULL;                          // Initialize children to NULL
    
    // Resize the array
    ((Node*)parent_node)->num_children += 1; // Increment the number of children of the parent node
    ((Node*)parent_node)->children = (Node**)realloc(((Node*)parent_node)->children, sizeof(Node*) * ((Node*)parent_node)->num_children); // Resize the array
    
    // Add the new node to the children array
    int last_index = ((Node*)parent_node)->num_children - 1;
    ((Node*)parent_node)->children[last_index] = new_node; // Assign the pointer to the new node
    
    //((Node*)parent_node)->num_children++; // Increment the number of children of the parent node
    
    ((Tree*)ACtree)->num_nodes += 1; // Increment the number of nodes in the tree
    
    return new_node; // Return the new node
}

// Print the tree (recursive function)
void print_tree(Node* node, int depth){
    // Print the current node value with indentation based on depth
    for(int i = 0; i < depth; i++){
        printf("  "); // Indent for each level of depth
    }
    printf("%c\n", node->value); // Print the node value

    // Recursively print the children of the current node
    for(int i = 0; i < ((Node*)node)->num_children; i++){
        print_tree(((Node*)node)->children[i], depth + 1); // Recursive call to print child nodes
    }
}


// Delete a node (recursive function)
void delete_node(Node* node){
    for(int i = 0; i < ((Node*)node)->num_children; i++){
        delete_node(*((Node*)node)->children + i);
    }

    free(((Node*)node)->children); // Free the children array
}

// Delete the tree
void delete_tree(Tree* ACtree){
    if(ACtree == NULL){
        return;
    }

    // Recursively delete all the node of the tree using delete_node
    for(int i = 0; i < ((Node*)((Tree*)ACtree)->root_node)->num_children; i++){
        delete_node(*(((Tree*)ACtree)->root_node)->children + i); // Recursively delete the children
    }

    free(((Tree*)ACtree)->root_node); // Free the root node
}

// Add a string to the tree
Tree* add_string(Tree* ACtree, char* keyword){
    // Create a new node for the root of the tree
    Node* parent_node = ((Tree*)ACtree)->root_node; // Get the root node of the tree

    // Iterate through each character in the string
    for(int i = 0; keyword[i] != '\0'; i++){

        // Cast to lower case
        char c = tolower((unsigned char)keyword[i]); // Convert to lowercase using tolower function
        
        // Add a new node to the tree for each character in the string
        parent_node = add_node(ACtree, parent_node, c); // Add the node to the tree
    }

    ((Node*)parent_node)->end_of_string = true; // Set the end_of_string flag to true for the last node

    return ACtree; // Return the tree
}

// Function to check if a character is a separator (whitespace, comma, period, etc.)
bool is_separator(char c){
    return (c == ' ' || c == ',' || c == '.' || c == '!' || c == '?' || c == ';' || c == ':' || c == '\t' || c == '\n');
}

// Function to print the word found (recursive function)
void match(Node* node){
    if(((Node* )node)->parent != NULL && ((Node*)node)->parent->value != '*'){
        match(((Node*)node)->parent); // Recursive call to print the parent node
    }
    printf("%c", ((Node*)node)->value);
}

// Perform a single iteration in the tree
Node* iter(Node* node, char input){

    // Check if there is a child with value = input
    for(int i = 0; i < ((Node*)node)->num_children; i++){
        Node* child = ((Node*)node)->children[i]; // Get the child node

        // printf("Value of child %c\n", child->value); // Print the value of the child node

        if(child->value == input){

            // printf("Found, I return the child\n");

            return child; // Return the child pointer
        }
    }

    return ((Node*)node)->fail_link; // Return the fail link if no child found
}

// Input parser
bool parser(char* input, int len, Tree* ACtree){
    bool eval = false;
    Node* current_node = ((Tree*)ACtree)->root_node; // Start from the root node
    // Iterate through the input, one character at time
    for(int i = 0; i < len; i++){
        // Cast the character to lower case
        char c = tolower((unsigned char)input[i]); // Convert to lowercase using tolower function
        
        current_node = iter(current_node, c);

        // Check if the current_node is equal to root
        if(((Node*)current_node)->parent == NULL){
            // I skip the rest of the word (i.e iterate until I find a white space or I finish the input)
            while(input[i] != ' ' && !is_separator(input[i]) && i < len){
                i++;
            }
            continue;
        }

        // Check if the current_node is a leaf node and if the next char is a white space or end of sting
        if(((Node*)current_node)->end_of_string && (i+1 == len || is_separator(input[i+1]))){
            // Print the word found
            Node * otp = current_node;
            printf("Found a match: \"");
            match(otp);
            printf("\"\n");
            current_node = (Node*)((Tree*)ACtree)->root_node; // Reset the current node to root
            eval = true;
        }
    }
    return eval;
}

// Main function to test the Aho-Corasick algorithm
int main(){
    // Create a new tree
    Tree* ACtree = create_tree();
    if (ACtree == NULL) {
        return 1; // Exit if tree creation fails
    }

    // Add strings to the tree
    add_string(ACtree, "HE\0");
    add_string(ACtree, "she\0");
    add_string(ACtree, "his\0");
    add_string(ACtree, "heR\0");

    printf("Tree created successfully\n");
    printf("Number of nodes in the tree: %d\n", ACtree->num_nodes);

    // Print tree
    printf("Tree structure:\n");
    print_tree(ACtree->root_node, 0); // Print the tree structure starting from the root node
    printf("\n");

    // Input string to search for
    char test_1[] = "his name is Albert.\0"; 
    char test_2[] = "Television rule the nation\0";
    char test_3[] = "Sheron is a doctor, she is a friend of mine\0";
    char test_4[] = "wherever I go here I am\0";
    char test_5[] = "history sheldon, herbe hehe!\0";
    char test_6[] = "#$%&/()=?\0"; // Test with special characters
    char test_7[] = "1 2 345 67 8 900\0";
    char test_8[] = "He is Marco. He is a friend of mine. His girlfriend is Marta. She is a nurse.\0";


    printf("Test 1: \"%s\"\n", test_1); // Print the input string
    if(!(parser(test_1, sizeof(test_1), ACtree))){
        printf("No match found\n", test_1); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns

    printf("Test 2: \"%s\"\n", test_2); // Print the input string
    if(!(parser(test_2, sizeof(test_2), ACtree))){
        printf("No match found\n", test_2); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns

    printf("Test 3: \"%s\"\n", test_3); // Print the input string
    if(!(parser(test_3, sizeof(test_3), ACtree))){
        printf("No match found\n", test_3); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns

    printf("Test 4: \"%s\"\n", test_4); // Print the input string
    if(!(parser(test_4, sizeof(test_4), ACtree))){
        printf("No match found\n", test_4); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns

    printf("Test 5: \"%s\"\n", test_5); // Print the input string
    if(!(parser(test_5, sizeof(test_5), ACtree))){
        printf("No match found\n", test_5); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns

    printf("Test 6: \"%s\"\n", test_6); // Print the input string
    if(!(parser(test_6, sizeof(test_6), ACtree))){
        printf("No match found\n", test_6); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns

    printf("Test 7: \"%s\"\n", test_7); // Print the input string
    if(!(parser(test_7, sizeof(test_7), ACtree))){
        printf("No match found\n", test_7); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns
   
    printf("Test 8: \"%s\"\n", test_8); // Print the input string
    if(!(parser(test_8, sizeof(test_8), ACtree))){
        printf("No match found\n", test_8); // Print the input string
    }
    printf("Initlial patterns: he, she, his, her\n\n"); // Print the initial patterns

    // Delete the tree to free memory
    delete_tree(ACtree);

    return 0;
}



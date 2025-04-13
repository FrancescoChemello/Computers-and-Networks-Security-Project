#ifndef AHOCORASICK_H
#define AHOCORASICK_H

#include <stdbool.h>

// Structure
typedef struct ACtree_t {
    struct node* root_node;
    int num_nodes;
} ACtree_t;

// Global variables
extern ACtree_t* ACtree;

// Public functions
ACtree_t* create_tree();
ACtree_t* add_string(ACtree_t* tree, char* pattern);
bool parser(char* input, int length, ACtree_t* tree);
void print_tree(ACtree_t* ACtree);
void delete_tree(ACtree_t* ACtree);

#endif // AHOCORASICK_H
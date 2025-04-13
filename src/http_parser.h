#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "ahocorasick\ahocorasick.h"

// Public functions
bool header_parser(char* header, int header_len);
bool header_body_parser(char* header, int header_len, char* body, int body_len);

#endif 
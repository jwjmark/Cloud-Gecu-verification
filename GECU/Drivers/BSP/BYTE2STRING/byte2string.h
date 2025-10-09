#include<stdlib.h>
#include<stdio.h>
#include<ctype.h>
#include<stdint.h>



//void StringToByte(char* source, uint8_t* dest, int sourceLen);

void ByteToString(const uint8_t* source, char* dest, int byteLen);

int hex_char_to_int(char c);

void hex_to_bytes(unsigned char* dest, const char* src, int byte_len);

void bytes_to_hex(char* dest, const unsigned char* src, int byte_len);
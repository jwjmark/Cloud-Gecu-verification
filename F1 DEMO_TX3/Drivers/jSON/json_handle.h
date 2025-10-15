#ifndef JSON_HANDLE_H
#define JSON_HANDLE_H

#include "cJSON.h"  // 确保包含 cJSON 库的头文件
#include <stdint.h>


void StringToByte(char* source, uint8_t* dest, int sourceLen);
void CreatePDUJson(cJSON *root, unsigned char *pdu, int pdu_Size);
void CreateMACJson(cJSON *root, unsigned char *mac, int mac_Size);
void CreateFVJson(cJSON *root, unsigned char *fv, int fv_Size);
uint8_t* AnalysisJson(cJSON *root,char* KeyName, int *arraysize);


#endif // JSON_ANALYSIS_H

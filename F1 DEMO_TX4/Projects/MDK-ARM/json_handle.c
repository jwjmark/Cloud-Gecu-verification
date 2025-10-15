#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "./jSON/cJSON.h"
#include "./jSON/json_handle.h"


void StringToByte(char* source, uint8_t* dest, int sourceLen)
{
	int i;
	uint8_t highByte, lowByte;

	for (i = 0; i < sourceLen; i += 2)
	{
		highByte = toupper(source[i]);
		lowByte  = toupper(source[i + 1]);

		if (highByte > 0x39)
			highByte -= 0x37;
		else
			highByte -= 0x30;

		if (lowByte > 0x39)
			lowByte -= 0x37;
		else
			lowByte -= 0x30;

		dest[i / 2] = (highByte << 4) | lowByte;
	}
	return ;
}

void CreatePDUJson(cJSON *root, unsigned char *pdu, int pdu_Size){

    //�������
    cJSON* pdujson = cJSON_CreateArray();

    for(int i=0; i<pdu_Size; i++){
        cJSON_AddItemToArray(pdujson, cJSON_CreateNumber(pdu[i]));
    }
    cJSON_AddItemToObject(root, "PDU", pdujson);
}
/*����MACֵ��ֵ*/
void CreateMACJson(cJSON *root, unsigned char *mac, int mac_Size){

    //�������
    cJSON* macjson = cJSON_CreateArray();
    for(int i=0; i<mac_Size; i++){
        cJSON_AddItemToArray(macjson, cJSON_CreateNumber(mac[i]));
    }
    cJSON_AddItemToObject(root, "MAC", macjson);    
}
/*�������ʶ�ֵ��ֵ*/
void CreateFVJson(cJSON *root, unsigned char *fv, int fv_Size){

    //�������
    cJSON* fvjson = cJSON_CreateArray();
    for(int i=0; i<fv_Size; i++){
        cJSON_AddItemToArray(fvjson, cJSON_CreateNumber(fv[i]));
    }
    cJSON_AddItemToObject(root, "FV", fvjson);    
}

/*��key����json������*/
uint8_t* AnalysisJson(cJSON *root,char* KeyName, int *arraysize){
    // ��ȡ JSON ������KEY��Ӧ������
    cJSON* jsonArray = cJSON_GetObjectItemCaseSensitive(root, KeyName);

    //��ȡ�����С
    *arraysize = cJSON_GetArraySize(jsonArray);
    
    //��̬�����ڴ����洢����
    uint8_t *resultArray = (uint8_t*)malloc(*arraysize * sizeof(uint8_t));

    //��������
    for(int i=0; i< *arraysize; i++){
        resultArray[i] = (uint8_t)cJSON_GetArrayItem(jsonArray, i)->valueint;//�������е�ÿһ����ֵ��ԭΪ�ֽ�
    }
    // ���ؽ������
    return resultArray;    
}
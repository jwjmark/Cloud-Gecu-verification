/*
  Copyright (c) 2009-2017 Dave Gamble and cJSON contributors

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include <stdint.h>



void CreatePDUJson(cJSON *root, unsigned char *pdu, int pdu_Size){

    //添加数组
    cJSON* pdujson = cJSON_CreateArray();

    for(int i=0; i<pdu_Size; i++){
        cJSON_AddItemToArray(pdujson, cJSON_CreateNumber(pdu[i]));
    }
    cJSON_AddItemToObject(root, "PDU", pdujson);    
}
/*创建MAC值键值*/
void CreateMACJson(cJSON *root, unsigned char *mac, int mac_Size){

    //添加数组
    cJSON* macjson = cJSON_CreateArray();
    for(int i=0; i<mac_Size; i++){
        cJSON_AddItemToArray(macjson, cJSON_CreateNumber(mac[i]));
    }
    cJSON_AddItemToObject(root, "MAC", macjson);    
}
/*创建新鲜度值键值*/
void CreateFVJson(cJSON *root, unsigned char *fv, int fv_Size){

    //添加数组
    cJSON* fvjson = cJSON_CreateArray();
    for(int i=0; i<fv_Size; i++){
        cJSON_AddItemToArray(fvjson, cJSON_CreateNumber(fv[i]));
    }
    cJSON_AddItemToObject(root, "FV", fvjson);    
}

/*按key解析json串内容*/
int* AnalysisJson(cJSON *root,char* KeyName){
    // 获取 JSON 对象中KEY对应的数组
    cJSON* item = cJSON_GetObjectItemCaseSensitive(root, KeyName);

    //获取数组大小
    int arraysize = cJSON_GetArraySize(item);
    
    //动态分配内存来存储数组
    int* resultArray = (int*)malloc(arraysize * sizeof(int));
    // 检查内存分配是否成功
    if (resultArray == NULL) {
        printf("Memory allocation failed!\n");
        return NULL;
    }

    //遍历数组
    for(int i=0; i< arraysize; i++){
        cJSON* arrayItem = cJSON_GetArrayItem(item, i);
        resultArray[i] = arrayItem->valueint;
        printf("arrayitem[%d]:%d\n", i, resultArray[i]);
    }

    // 返回结果数组
    return resultArray;
    
}


static int printfjson(cJSON *root){

    //将json对象转为字符串
    char* jsonOut = cJSON_Print(root);
    //打印json字符串
    printf("jsonOut:\n###%s***\n", jsonOut);
    
    //释放内存
    // cJSON_Delete(root);
    // free(jsonOut);
    // return 0;

}

int CJSON_CDECL main(void)
{
    // /* print the version */
    // printf("Version: %s\n", cJSON_Version());

    // /* Now some samplecode for building objects concisely: */
    // create_objects();

    uint8_t pdu[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};//之后替换为CAN加密后的数据
    uint8_t mac[] = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};//之后替换为MAC消息验证码
    uint8_t fv[] = {0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};//之后替换为FV新鲜度值
    // 创建 JSON 对象
    cJSON *object = cJSON_CreateObject();    //创建JSON指针头结点
    CreatePDUJson(object, pdu, sizeof(pdu));
    CreateMACJson(object, mac, sizeof(mac));
    CreateFVJson(object, fv, sizeof(fv));


    //解析JSON串,输出数组，处理后记得释放内存free(resultArray)
    AnalysisJson(object,"MAC");

    printfjson(object);

    return 0;
}
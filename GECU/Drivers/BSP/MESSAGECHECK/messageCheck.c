
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "./SHA256/sha256.h"
#include "./ESP8266/esp8266.h"
#include "./MESSAGECHECK/messageCheck.h"
#include "./CJSON/cJSON.h"  




void print_errorinfo(int errornum){
    switch (errornum)
    {
    case MSG_CHECK_ERROR_JSONTYPE:
        printf("%s\n","MSG_CHECK_ERROR_JSONTYPE");
        break;
    case MSG_CHECK_ERROR_JSONKEY:
        printf("%s\n","MSG_CHECK_ERROR_JSONKEY");
        break;
    case MSG_CHECK_ERROR_DIGEST:
        printf("%s\n","MSG_CHECK_ERROR_DIGEST");
        break;
    case MSG_CHECK_ERROR_TIMEVAL:
        printf("%s\n","MSG_CHECK_ERROR_TIMEVAL");
        break;
    case MSG_CHECK_ERROR_KEY:
        printf("%s\n","MSG_CHECK_ERROR_KEY");
        break;

    default:
        break;
    }
}

int check_json_keys(cJSON *json, char *required_keys[], int num_required_keys) {
    // 检查 JSON 对象是否为 NULL
    // printf("-----0");
    if (json == NULL || !cJSON_IsObject(json)) {
        return 0; // 不是一个有效的 JSON 对象
    }
    // printf("-----1");
    // 检查 JSON 对象中的键数量
    int key_count = cJSON_GetArraySize(json);
    if (key_count != num_required_keys) {
        return 0; // 键的数量不匹配
    }
    // printf("-----2");
    // 检查是否只包含特定的键
    cJSON *item;
    cJSON_ArrayForEach(item, json) {
        int found = 0;
        for (int i = 0; i < num_required_keys; i++) {
            if (strcmp(item->string, required_keys[i]) == 0) {
                found = 1; // 找到匹配的键
                // printf("found %s\n", required_keys[i]);
                break;
            }
        }
        if (!found) {
            return 0; // 发现了不在要求中的键
        }
    }

    return 1; // 只包含特定的键
}


int CheckMessage_ev2cs_auth (void * jsondata){

//    cJSON *json = jsondata;
//    if (!json) {
//        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
//        return MSG_CHECK_ERROR_JSONTYPE;
//    }

//     // 定义需要检查的键
//    const char *required_keys[] = {"keytag", "datalen","data","timestap","digest"};
//    int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);

//    // 检查 JSON 对象中的键
//    if (check_json_keys(json, required_keys, num_required_keys) != 1) {
//        printf("error: check_json_keys\n");
//        return MSG_CHECK_ERROR_KEY;
//    }        

//    cJSON *digest = cJSON_GetObjectItem(json, "digest");
//    if (cJSON_IsString(digest) && (digest->valuestring != NULL)) {
//        printf("digest: %s\n", digest->valuestring);
//    }
//    cJSON *keytag = cJSON_GetObjectItem(json, "keytag");
//    if (cJSON_IsString(keytag) && (keytag->valuestring != NULL)) {
//        printf("keytag: %s\n", keytag->valuestring);
//    }
//    cJSON *datalen = cJSON_GetObjectItem(json, "datalen");
//    if (cJSON_IsNumber(datalen) ) {
//        printf("datalen: %d\n", datalen->valueint);
//    }
//    cJSON *data = cJSON_GetObjectItem(json, "data");
//    if (cJSON_IsString(data) && (data->valuestring != NULL)) {
//        printf("data: %s\n", data->valuestring);
//    }
//    cJSON *timestap = cJSON_GetObjectItem(json, "timestap");
//    if (cJSON_IsString(timestap) && (timestap->valuestring != NULL)) {
//        printf("timestap: %s\n", timestap->valuestring);
//    }


//    //开始验证哈希值
//    unsigned char hash_inbuf[512] = { 0 };
//	unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
//	memset(hash_outbuff,0,32);

//    // 使用 strcat 函数进行字符串拼接
//    strcat(hash_inbuf, keytag->valuestring);
//    unsigned char stred_len[10] = { 0 };
//    // 使用 sprintf 将整型转换为字符串
//    sprintf(stred_len, "%d", datalen->valueint);
//    strcat(hash_inbuf, stred_len);
//    strcat(hash_inbuf, data->valuestring);
//    strcat(hash_inbuf, timestap->valuestring);

//    printf("\nhash_inbuf:%s\n", hash_inbuf);
//	// puts("start sha256 hash \n");
////	sha256(hash_inbuf,strlen(hash_inbuf),hash_outbuff);
//    char strbuf[65] = {0};
//    ByteToString(hash_outbuff,strbuf,32);

//    if(strcmp(strbuf, digest->valuestring) != 0)
//    {
//        return MSG_CHECK_ERROR_DIGEST;
//    }
    return MSG_CHECK_OK;
}

int CheckMessage_cs2es_auth (void * jsondata){

//    cJSON *json = jsondata;
//    if (!json) {
//        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
//        return MSG_CHECK_ERROR_JSONTYPE;
//    }

//     // 定义需要检查的键
//    const char *required_keys[] = {"keytag","CID","evMsg","timestap","digest"};
//    int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);

//    // 检查 JSON 对象中的键
//    if (check_json_keys(json, required_keys, num_required_keys) != 1) {
//        printf("error: check_json_keys\n");
//        return MSG_CHECK_ERROR_KEY;
//    }        

//    cJSON *digest = cJSON_GetObjectItem(json, "digest");
//    if (cJSON_IsString(digest) && (digest->valuestring != NULL)) {
//        printf("digest: %s\n", digest->valuestring);
//    }
//    cJSON *keytag = cJSON_GetObjectItem(json, "keytag");
//    if (cJSON_IsString(keytag) && (keytag->valuestring != NULL)) {
//        printf("keytag: %s\n", keytag->valuestring);
//    }

//    cJSON *CID = cJSON_GetObjectItem(json, "CID");
//    if (cJSON_IsString(CID) && (CID->valuestring != NULL)) {
//        printf("CID: %s\n", CID->valuestring);
//    }
//    cJSON *timestap = cJSON_GetObjectItem(json, "timestap");
//    if (cJSON_IsString(timestap) && (timestap->valuestring != NULL)) {
//        printf("timestap: %s\n", timestap->valuestring);
//    }
//    cJSON *evMsg = cJSON_GetObjectItem(json, "evMsg");
//    if (cJSON_IsString(evMsg) && (evMsg->valuestring != NULL)) {
//        printf("evMsg: %s\n", evMsg->valuestring);
//    }


//    //开始验证哈希值
//    unsigned char hash_inbuf[512] = { 0 };
//	unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
//	memset(hash_outbuff,0,32);

//    // 使用 strcat 函数进行字符串拼接
//    
//    // unsigned char stred_len[10] = { 0 };
//    // 使用 sprintf 将整型转换为字符串
//    // sprintf(stred_len, "%d", datalen->valueint);
//    strcat(hash_inbuf, CID->valuestring);
//    strcat(hash_inbuf, keytag->valuestring);
//    strcat(hash_inbuf, timestap->valuestring);
//    strcat(hash_inbuf, evMsg->valuestring);

//    printf("\nhash_inbuf:%s\n", hash_inbuf);
//	// puts("start sha256 hash \n");
////	sha256(hash_inbuf,strlen(hash_inbuf),hash_outbuff);
//    char strbuf[65] = {0};
//    ByteToString(hash_outbuff,strbuf,32);

//    if(strcmp(strbuf, digest->valuestring) != 0)
//    {
//        return MSG_CHECK_ERROR_DIGEST;
//    }
    return MSG_CHECK_OK;
}

int CheckMessage_es2cs_auth (void * jsondata){   //别忘了改成vcs2gecu
    
    cJSON *json = jsondata;
    if (!json) 
    {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return MSG_CHECK_ERROR_JSONTYPE;
    }    
    if(esp_rxflag == 0){
         // 定义需要检查的键
        char *required_keys[] = {"PGID", "QCG","MAC"};
        int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);
        
        uint16_t pgidstr[128];
        uint16_t qcgstr[128];
        uint16_t macstr[128];

        // 检查 JSON 对象中的键
        if (check_json_keys(json, required_keys, num_required_keys) != 1) {
            
            printf("error: check_json_keys\n");
            return MSG_CHECK_ERROR_KEY;
        }        

        cJSON *pgid = cJSON_GetObjectItem(json, "PGID");
//        if (cJSON_IsString(pgid) && (pgid->valuestring != NULL)) {
//            printf("pgid: %s\n", pgid->valuestring);
//        }
        cJSON *qcg = cJSON_GetObjectItem(json, "QCG");
//        if (cJSON_IsString(qcg) && (qcg->valuestring != NULL)) {
//            printf("qcg: %s\n", qcg->valuestring);
//        }
        cJSON *mac = cJSON_GetObjectItem(json, "MAC");
//        if (cJSON_IsString(mac) && (mac->valuestring != NULL)) {
//            printf("MAC: %s\n", mac->valuestring);
//        }

        //开始验证哈希值
        unsigned char hash_inbuf[512] = { 0 };
        unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
        memset(hash_inbuf , 0 ,sizeof(hash_inbuf));
        
        // 使用 strcat 函数进行字符串拼接
        strcat((char *)hash_inbuf, pgid->valuestring);
        strcat((char *)hash_inbuf, qcg->valuestring);

        char strbuf[65] = {0};        
        char *result = Sha256_auth(hash_inbuf);
        if (result != NULL) 
        {
            strncpy(strbuf, result, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
            strbuf[64] = '\0';  // 确保字符串以 '\0' 结束

        }

        if(strcmp(strbuf, mac->valuestring) != 0)
        {
            return MSG_CHECK_ERROR_DIGEST;
        }
        else
        {
            return MSG_CHECK_OK;
        }
    }else if(esp_rxflag == 1)
    {
         // 定义需要检查的键
        char *required_keys[] = {"PGID", "M2","MAC"};
        int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);
        
        uint16_t pgidstr[128];
        uint16_t qcgstr[128];
        uint16_t macstr[128];

        // 检查 JSON 对象中的键
        if (check_json_keys(json, required_keys, num_required_keys) != 1) {
            
            printf("error: check_json_keys\n");
            return MSG_CHECK_ERROR_KEY;
        }        

        cJSON *pgid = cJSON_GetObjectItem(json, "PGID");
//        if (cJSON_IsString(pgid) && (pgid->valuestring != NULL)) {
//            printf("pgid: %s\n", pgid->valuestring);
//        }
        cJSON *m2 = cJSON_GetObjectItem(json, "M2");
//        if (cJSON_IsString(qcg) && (qcg->valuestring != NULL)) {
//            printf("qcg: %s\n", qcg->valuestring);
//        }
        cJSON *mac = cJSON_GetObjectItem(json, "MAC");
//        if (cJSON_IsString(mac) && (mac->valuestring != NULL)) {
//            printf("MAC: %s\n", mac->valuestring);
//        }

        //开始验证哈希值
        unsigned char hash_inbuf[512] = { 0 };
        unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
        memset(hash_inbuf , 0 ,sizeof(hash_inbuf));
        
        // 使用 strcat 函数进行字符串拼接
        strcat((char *)hash_inbuf, pgid->valuestring);
        strcat((char *)hash_inbuf, m2->valuestring);

        char strbuf[65] = {0};        
        char *result = Sha256_auth(hash_inbuf);
        if (result != NULL) 
        {
            strncpy(strbuf, result, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
            strbuf[64] = '\0';  // 确保字符串以 '\0' 结束

        }

        if(strcmp(strbuf, mac->valuestring) != 0)
        {
            return MSG_CHECK_ERROR_DIGEST;
        }
        else
        {
            return MSG_CHECK_OK;
        }
    }
}

//void AuthMsg_callback_EV2CS(char* msg){
//    // // 解析JSON
////    cJSON *json_evAuth = cJSON_Parse(msg);
////    if (!json_evAuth) {
////        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
////        return ;
////    }
////    // 检查消息格式是否正确
////    int rt = CheckMessage_ev2cs_auth(json_evAuth);
////    if ( rt!= MSG_CHECK_OK) {
////        printf("Error CheckMessage_ev2cs_auth: \n");
////        print_errorinfo(rt);
////        return ;
////    }


////    time_t current_time;
////    struct tm *local_time;
////    char time_buffer[100];
////    // 获取当前时间戳
////    current_time = time(NULL);
////    // 转换为本地时间
////    local_time = localtime(&current_time);
////    // 格式化时间输出
////    strftime(time_buffer, sizeof(time_buffer), "%Y.%m.%d/%H:%M.%S", local_time);
////    // 打印详细时间
////    printf("Current local time: %s", time_buffer);

//    unsigned char hash_inbuf[512] = { 0 };
//    unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
//    memset(hash_outbuff,0,32);

//    // 使用 strcat 函数进行字符串拼接
//    strcat(hash_inbuf, CSID);
//    strcat(hash_inbuf, KEYTAG);
//    strcat(hash_inbuf, time_buffer);
//    strcat(hash_inbuf, msg);
//    printf("\nhash_inbuf:%s\n", hash_inbuf);
//    // puts("start sha256 hash \n");
//    sha256(hash_inbuf,strlen(hash_inbuf),hash_outbuff);
//    char strbuf[65] = {0};
//    ByteToString(hash_outbuff,strbuf,32);
//    // 构建认证消息内容.
//    // cJSON *root = NULL;

//    // /* Our "Video" datatype: */
//    // root = cJSON_CreateObject();

//    // cJSON_AddStringToObject(root, "keytag", KEYTAG);
//    // // cJSON_AddNumberToObject(root, "deviceid", 001);
//    // // cJSON_AddNumberToObject(root, "datalen", text_buf_len);
//    // cJSON_AddStringToObject(root, "CID", CSID);
//    // cJSON_AddStringToObject(root, "timestap", time_buffer);
//    // cJSON_AddStringToObject(root, "digest",strbuf);
//    // cJSON_AddStringToObject(root, "evMsg", msg);
//    // /* declarations */
//    // char *out = NULL;
//    // char *buf = NULL;
//    // char *buf_fail = NULL;
//    // size_t len = 0;
//    // size_t len_fail = 0;
//    /* formatted print */
//    // out = cJ
//	char *out1 = NULL;
//    char *out2 = NULL;
//   // 创建两个新的JSON对象
//    cJSON *json_part1 = cJSON_CreateObject();
//    cJSON *json_part2 = cJSON_CreateObject();
//    cJSON_AddNumberToObject(json_part1, "f", 1);
//    cJSON_AddStringToObject(json_part1, "keytag", KEYTAG);
//    cJSON_AddStringToObject(json_part1, "CID", CSID);
//    cJSON_AddStringToObject(json_part1, "timestap", time_buffer);
//    cJSON_AddStringToObject(json_part1, "digest",strbuf);
//    out1 = cJSON_PrintUnformatted(json_part1);

//    cJSON_AddNumberToObject(json_part2, "f", 2);
//    cJSON_AddStringToObject(json_part2, "evMsg", msg);
//    out2 = cJSON_PrintUnformatted(json_part2);

//    MQTTClient_message pubmsg = MQTTClient_message_initializer;
//    pubmsg.payload = out1;
//    pubmsg.payloadlen = strlen(out1);
//    pubmsg.qos = QOS;
//    pubmsg.retained = 0;
//    
//    MQTTClient_deliveryToken token;
//    MQTTClient_publishMessage(client, "v2g/cs2es", &pubmsg, &token);

//    pubmsg.payload = out2;
//    pubmsg.payloadlen = strlen(out2);
//    pubmsg.qos = QOS;
//    pubmsg.retained = 0;
//    
//    MQTTClient_publishMessage(client, "v2g/cs2es", &pubmsg, &token);
//    // printf("Waiting for publication of %s\n"
//    //     "on topic %s for client with ClientID: %s\n",
//    //     pubmsg.payload, TOPIC, CLIENTID);
//    // rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
//    // printf("Message with delivery token %d delivered\n", token);
//    // 释放 JSON 对象内存

//    free(out1); // 释放字符串内存
//    free(out2); // 释放字符串内存

//    cJSON_Delete(json_part1);
//    cJSON_Delete(json_part2);
//}	

int findSubstring(const char *str, const char *substr) {
    // 获取长字符串和子串的长度
    int strLen = strlen(str);
    int substrLen = strlen(substr);
    
    // 如果子串比长字符串还长，直接返回-1
    if (substrLen > strLen) {
        return -1;
    }

    // 遍历长字符串，查找子串
    for (int i = 0; i <= strLen - substrLen; i++) {
        // 比较当前字符开始的子串是否与目标子串相同
        if (strncmp(&str[i], substr, substrLen) == 0) {
            return i; // 找到子串，返回起始位置
        }
    }

    return -1; // 没有找到子串，返回-1
}


CJSON_PUBLIC(cJSON *) cJSON_Parse_es2cs(const char *msg)
	{
    int position_KDIV = findSubstring(msg, "KDIV");
    if (position_KDIV != -1) {
        printf("Substring position_KDIV found at position: %d\n", position_KDIV);
    } else {
        printf("Substring position_KDIV not found.\n");
    }

    int position_KDIC = findSubstring(msg, "KDIC");
    if (position_KDIC != -1) {
        printf("Substring position_KDIC found at position: %d\n", position_KDIC);
    } else {
        printf("Substring position_KDIC not found.\n");
    }

    int position_timestap = findSubstring(msg, "timestap");
    if (position_timestap != -1) {
        printf("Substring timetsap found at position: %d\n", position_timestap);
    } else {
        printf("Substring timetsap not found.\n");
    }

    int position_dig2ev = findSubstring(msg, "dig2ev");
    if (position_dig2ev != -1) {
        printf("Substring position_dig2ev found at position: %d\n", position_dig2ev);
    } else {
        printf("Substring position_dig2ev not found.\n");
    }

    int position_dig2cs = findSubstring(msg, "dig2cs");
    if (position_dig2cs != -1) {
        printf("Substring position_dig2cs found at position: %d\n", position_dig2cs);
    } else {
        printf("Substring position_dig2cs not found.\n");
    }

    char KDIV[32+1] = {0};
    char KDIC[32+1] = {0};
    char timetsap[25+1] = {0};
    char dig2ev[64+1] = {0};
    char dig2cs[64+1] = {0};

    memcpy(KDIV,msg+position_KDIV+strlen("KDIV")+3,32);
    memcpy(KDIC,msg+position_KDIC+strlen("KDIC")+3,32);
    memcpy(timetsap,msg+position_timestap+strlen("timestap")+3,19);
    memcpy(dig2ev,msg+position_dig2ev+strlen("dig2ev")+3,64);
    memcpy(dig2cs,msg+position_dig2cs+strlen("dig2cs")+3,64);
	printf("KDIV:%s\n",KDIV);
	printf("KDIC:%s\n",KDIC);
	printf("timetsap:%s\n",timetsap);
	printf("dig2ev:%s\n",dig2ev);	
	printf("dig2cs:%s\n",dig2cs);
// 注意内存释放
    cJSON *json_es2cs = cJSON_CreateObject();
	if(json_es2cs == NULL)
	{
		printf("fail5");
	}
    cJSON_AddStringToObject(json_es2cs, "KDIV", KDIV);
    cJSON_AddStringToObject(json_es2cs, "KDIC", KDIC);
    cJSON_AddStringToObject(json_es2cs, "timestap", timetsap);
    cJSON_AddStringToObject(json_es2cs, "dig2ev",dig2ev);
    cJSON_AddStringToObject(json_es2cs, "dig2cs",dig2cs);

    char *out = cJSON_PrintUnformatted(json_es2cs);
    char *escaped_out = add_escape_characters(out);

    printf("json_es2cs: %s\n", escaped_out);
    return json_es2cs;
}




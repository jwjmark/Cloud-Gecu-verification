#include"messageCheck.h"



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

int check_json_keys(cJSON *json, const char *required_keys[], int num_required_keys) {
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
    // MQTTClient_message *message = jsondata;

    cJSON *json = jsondata;
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return MSG_CHECK_ERROR_JSONTYPE;
    }

     // 定义需要检查的键
    const char *required_keys[] = {"keytag","data","timestap","digest"};
    int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);

    // 检查 JSON 对象中的键
    if (check_json_keys(json, required_keys, num_required_keys) != 1) {
        printf("error: check_json_keys\n");
        return MSG_CHECK_ERROR_KEY;
    }        

    cJSON *digest = cJSON_GetObjectItem(json, "digest");
    if (cJSON_IsString(digest) && (digest->valuestring != NULL)) {
        printf("digest: %s\n", digest->valuestring);
    }
    cJSON *keytag = cJSON_GetObjectItem(json, "keytag");
    if (cJSON_IsString(keytag) && (keytag->valuestring != NULL)) {
        printf("keytag: %s\n", keytag->valuestring);
    }
    // cJSON *datalen = cJSON_GetObjectItem(json, "datalen");
    // if (cJSON_IsNumber(datalen) ) {
    //     printf("datalen: %d\n", datalen->valueint);
    // }
    cJSON *data = cJSON_GetObjectItem(json, "data");
    if (cJSON_IsString(data) && (data->valuestring != NULL)) {
        printf("data: %s\n", data->valuestring);
    }
    cJSON *timestap = cJSON_GetObjectItem(json, "timestap");
    if (cJSON_IsString(timestap) && (timestap->valuestring != NULL)) {
        printf("timestap: %s\n", timestap->valuestring);
    }


    //开始验证哈希值
    unsigned char hash_inbuf[512] = { 0 };
	unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
	memset(hash_outbuff,0,32);

    // 使用 strcat 函数进行字符串拼接
    strcat((char*)hash_inbuf, keytag->valuestring);
    // unsigned char stred_len[10] = { 0 };
    // // 使用 sprintf 将整型转换为字符串
    // sprintf(stred_len, "%d", datalen->valueint);
    // strcat(hash_inbuf, stred_len);
    strcat((char*)hash_inbuf, data->valuestring);
    strcat((char*)hash_inbuf, timestap->valuestring);

    printf("\nhash_inbuf:%s\n", hash_inbuf);
	// puts("start sha256 hash \n");
	sha256(hash_inbuf,strlen((char*)hash_inbuf),hash_outbuff);
    char strbuf[65] = {0};
    ByteToString(hash_outbuff,strbuf,32);

    if(strcmp(strbuf, digest->valuestring) != 0)
    {
        return MSG_CHECK_ERROR_DIGEST;
    }
    return MSG_CHECK_OK;
}

int CheckMessage1_gecu2vcs_auth (void * jsondata){
    // MQTTClient_message *message = jsondata;

    cJSON *json = jsondata;
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return MSG_CHECK_ERROR_JSONTYPE;
    }

     // 定义需要检查的键
    const char *required_keys[] = {"PGID","M1","MAC"};
    int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);

    // 检查 JSON 对象中的键
    if (check_json_keys(json, required_keys, num_required_keys) != 1) {
        printf("error: check_json_keys\n");
        return MSG_CHECK_ERROR_KEY;
    }    
    
    cJSON *PGID = cJSON_GetObjectItem(json, "PGID");
    if (cJSON_IsString(PGID) && (PGID->valuestring != NULL)) {
        printf("PGID: %s\n", PGID->valuestring);
    }

    cJSON *M1 = cJSON_GetObjectItem(json, "M1");
    if (cJSON_IsString(M1) && (M1->valuestring != NULL)) {
        printf("M1: %s\n", M1->valuestring);
    }
    
    
    cJSON *MAC = cJSON_GetObjectItem(json, "MAC");
    if (cJSON_IsString(MAC) && (MAC->valuestring != NULL)) {
        printf("MAC: %s\n", MAC->valuestring);
    }


    //开始验证MAC值（哈希值）
    unsigned char hash_inbuf[512] = { 0 };
	unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
	memset(hash_outbuff,0,32);

    strcat((char*)hash_inbuf, PGID->valuestring);
    strcat((char*)hash_inbuf, M1->valuestring);

    // printf("\nhash_inbuf:%s\n", hash_inbuf);
	// puts("start sha256 hash \n");
	sha256(hash_inbuf,strlen((char*)hash_inbuf),hash_outbuff);

    char strbuf[65] = {0};
    ByteToString(hash_outbuff,strbuf,32);
    // printf("\n计算出的MAC值:%s\n", strbuf);

    if(strcmp(strbuf, MAC->valuestring) != 0)
    {
        return MSG_CHECK_ERROR_DIGEST;
    }
    return MSG_CHECK_OK;
}

int CheckMessage2_gecu2vcs_auth (void * jsondata){
    // MQTTClient_message *message = jsondata;

    cJSON *json = jsondata;
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return MSG_CHECK_ERROR_JSONTYPE;
    }

     // 定义需要检查的键
    const char *required_keys[] = {"PGID","M1","QGC","MAC"};
    int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);

    // 检查 JSON 对象中的键
    if (check_json_keys(json, required_keys, num_required_keys) != 1) {
        printf("error: check_json_keys\n");
        return MSG_CHECK_ERROR_KEY;
    }    
    
    cJSON *PGID = cJSON_GetObjectItem(json, "PGID");
    if (cJSON_IsString(PGID) && (PGID->valuestring != NULL)) {
        printf("PGID: %s\n", PGID->valuestring);
    }

    cJSON *M1 = cJSON_GetObjectItem(json, "M1");
    if (cJSON_IsString(M1) && (M1->valuestring != NULL)) {
        printf("M_1: %s\n", M1->valuestring);
    }

    cJSON *QGC = cJSON_GetObjectItem(json, "QGC");
    if (cJSON_IsString(QGC) && (QGC->valuestring != NULL)) {
        printf("QGC: %s\n", QGC->valuestring);
    }
    
    cJSON *MAC = cJSON_GetObjectItem(json, "MAC");
    if (cJSON_IsString(MAC) && (MAC->valuestring != NULL)) {
        printf("MAC: %s\n", MAC->valuestring);
    }

    //开始验证MAC值（哈希值）
    unsigned char hash_inbuf[512] = { 0 };
	unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
	memset(hash_outbuff,0,32);

    strcat((char*)hash_inbuf, PGID->valuestring);
    strcat((char*)hash_inbuf, M1->valuestring);
    strcat((char*)hash_inbuf, QGC->valuestring);

	sha256(hash_inbuf,strlen((char*)hash_inbuf),hash_outbuff);

    char strbuf[65] = {0};
    ByteToString(hash_outbuff,strbuf,32);
    // printf("\n计算出的MAC值:%s\n", strbuf);

    if(strcmp(strbuf, MAC->valuestring) != 0)
    {
        return MSG_CHECK_ERROR_DIGEST;
    }
    else{
        printf("MAC值验证成功\n");
    }
    return MSG_CHECK_OK;
}

int CheckMessage3_gecu2vcs_auth (void * jsondata){
    cJSON *json = jsondata;
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return MSG_CHECK_ERROR_JSONTYPE;
    }

    // 定义需要检查的键: PGID, M3, C1, MAC
    const char *required_keys[] = {"PGID", "M3", "C1", "MAC"};
    int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);

    if (check_json_keys(json, required_keys, num_required_keys) != 1) {
        printf("error: check_json_keys for ECU auth message\n");
        return MSG_CHECK_ERROR_KEY;
    }

    cJSON *PGID = cJSON_GetObjectItem(json, "PGID");
    cJSON *M3 = cJSON_GetObjectItem(json, "M3");
    cJSON *C1 = cJSON_GetObjectItem(json, "C1");
    cJSON *MAC = cJSON_GetObjectItem(json, "MAC");

    // 开始验证MAC值 H(PGID || M3 || C1)
    unsigned char hash_inbuf[1024] = { 0 };
    unsigned char hash_outbuff[32];
    memset(hash_outbuff, 0, 32);

    strcat((char*)hash_inbuf, PGID->valuestring);
    strcat((char*)hash_inbuf, M3->valuestring);
    strcat((char*)hash_inbuf, C1->valuestring);

    sha256(hash_inbuf, strlen((char*)hash_inbuf), hash_outbuff);

    char strbuf[65] = {0};
    ByteToString(hash_outbuff, strbuf, 32);
    printf("  Calculated MAC: %s\n", strbuf);
    printf("  Received MAC:   %s\n", MAC->valuestring);

    if (strcmp(strbuf, MAC->valuestring) != 0)
    {
        return MSG_CHECK_ERROR_DIGEST;
    }
    else
    {
        printf("  MAC verification successful\n");
        return MSG_CHECK_OK;
    }
    
}

int CheckMessage_es2cs_auth (void * jsondata){
    // MQTTClient_message *message = jsondata;

    cJSON *json = jsondata;
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return MSG_CHECK_ERROR_JSONTYPE;
    }

     // 定义需要检查的键
    const char *required_keys[] = {"KDIV", "KDIC","timestap","dig2cs","dig2ev"};
    int num_required_keys = sizeof(required_keys) / sizeof(required_keys[0]);

    // 检查 JSON 对象中的键
    if (check_json_keys(json, required_keys, num_required_keys) != 1) {
        printf("error: check_json_keys\n");
        return MSG_CHECK_ERROR_KEY;
    }        

    cJSON *dig2cs = cJSON_GetObjectItem(json, "dig2cs");
    if (cJSON_IsString(dig2cs) && (dig2cs->valuestring != NULL)) {
        printf("dig2cs: %s\n", dig2cs->valuestring);
    }
    cJSON *dig2ev = cJSON_GetObjectItem(json, "dig2ev");
    if (cJSON_IsString(dig2ev) && (dig2ev->valuestring != NULL)) {
        printf("dig2ev: %s\n", dig2ev->valuestring);
    }
    cJSON *kdiv = cJSON_GetObjectItem(json, "KDIV");
    if (cJSON_IsString(kdiv) && (kdiv->valuestring != NULL)) {
        printf("kdiv: %s\n", kdiv->valuestring);
    }
    cJSON *kdic = cJSON_GetObjectItem(json, "KDIC");
    if (cJSON_IsString(kdic) && (kdic->valuestring != NULL)) {
        printf("kdic: %s\n", kdic->valuestring);
    }
    cJSON *timestap = cJSON_GetObjectItem(json, "timestap");
    if (cJSON_IsString(timestap) && (timestap->valuestring != NULL)) {
        printf("timestap: %s\n", timestap->valuestring);
    }


    //开始验证哈希值
    unsigned char hash_inbuf[512] = { 0 };
	unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
	memset(hash_outbuff,0,32);

    // 使用 strcat 函数进行字符串拼接
    strcat((char*)hash_inbuf, kdiv->valuestring);
    strcat((char*)hash_inbuf, kdic->valuestring);
    strcat((char*)hash_inbuf, timestap->valuestring);
    strcat((char*)hash_inbuf, dig2ev->valuestring);

    printf("\nhash_inbuf:%s\n", (char*)hash_inbuf);
	// puts("start sha256 hash \n");
    sha256(hash_inbuf, strlen((char*)hash_inbuf), hash_outbuff);
    char strbuf[65] = {0};
    ByteToString(hash_outbuff,strbuf,32);

    if(strcmp(strbuf, dig2cs->valuestring) != 0)
    {
        return MSG_CHECK_ERROR_DIGEST;
    }
    return MSG_CHECK_OK;
}


CJSON_PUBLIC(cJSON *) cJSON_Parse_ev2cs(const char *msg){
    int position_keytag = findSubstring(msg, "keytag");
    if (position_keytag != -1) {
        printf("Substring keytag found at position: %d\n", position_keytag);
    } else {
        printf("Substring keytag not found.\n");
    }

    int position_data = findSubstring(msg, "data");
    if (position_data != -1) {
        printf("Substring data found at position: %d\n", position_data);
    } else {
        printf("Substring data not found.\n");
    }

    int position_timestap = findSubstring(msg, "timestap");
    if (position_timestap != -1) {
        printf("Substring timetsap found at position: %d\n", position_timestap);
    } else {
        printf("Substring timetsap not found.\n");
    }

    int position_digest = findSubstring(msg, "digest");
    if (position_digest != -1) {
        printf("Substring digest found at position: %d\n", position_digest);
    } else {
        printf("Substring digest not found.\n");
    }

    char keytag[32] = {0};
    char data[64+1] = {0};
    char timetsap[25+1] = {0};
    char digest[64+1] = {0};

    memcpy(keytag,msg+position_keytag+strlen("keytag")+3,9);
    memcpy(data,msg+position_data+strlen("data")+3,32);
    memcpy(timetsap,msg+position_timestap+strlen("timestap")+3,19);
    memcpy(digest,msg+position_digest+strlen("digest")+3,64);

    // 注意内存释放
    cJSON *json_ev2cs = cJSON_CreateObject();
    cJSON_AddStringToObject(json_ev2cs, "keytag", keytag);
    cJSON_AddStringToObject(json_ev2cs, "data", data);
    cJSON_AddStringToObject(json_ev2cs, "timestap", timetsap);
    cJSON_AddStringToObject(json_ev2cs, "digest",digest);

    char *out = cJSON_PrintUnformatted(json_ev2cs);

    printf("json_ev2cs: %s\n", out);
    return json_ev2cs;
}

CJSON_PUBLIC(cJSON *) cJSON_Parse_es2cs(const char *msg){
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

    // 注意内存释放
    cJSON *json_es2cs = cJSON_CreateObject();
    cJSON_AddStringToObject(json_es2cs, "KDIV", KDIV);
    cJSON_AddStringToObject(json_es2cs, "KDIC", KDIC);
    cJSON_AddStringToObject(json_es2cs, "timestap", timetsap);
    cJSON_AddStringToObject(json_es2cs, "dig2ev",dig2ev);
    cJSON_AddStringToObject(json_es2cs, "dig2cs",dig2cs);

    char *out = cJSON_PrintUnformatted(json_es2cs);

    printf("json_es2cs: %s\n", out);
    return json_es2cs;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> 
#include <time.h>
#include <inttypes.h>
#include <unistd.h>
#include "MQTTClient.h"
#include <stdarg.h>
#include "cJSON.h"
#include "messageCheck.h"

#include"sha256.h"
#include"sm4.h"
#include"byte2string.h"


// 配置文件信息
static cJSON *configjson;

char* ADDRESS = NULL;
char* CLIENTID = NULL;
char* TOPIC = NULL;
int QOS = 0;

int receiveflag = 0;
// #define QOS         2
#define TIMEOUT     10000L

volatile MQTTClient_deliveryToken deliveredtoken;
MQTTClient client;
MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
int rc;





// 生成伪随机字符
char generate_random_char() {
    int type = rand() % 3; // 0: lowercase letter, 1: uppercase letter, 2: digit
    if (type == 0) {
        return 'a' + (rand() % 26); // 生成小写字母
    } else if (type == 1) {
        return 'A' + (rand() % 26); // 生成大写字母
    } else {
        return '0' + (rand() % 10); // 生成数字
    }
}

void generate_random_string(char *str, int length) {
    for (int i = 0; i < length; i++) {
        str[i] = generate_random_char();
    }
    str[length] = '\0'; // 字符串结束符
}

//检索是否存在指定键，输出对应值
void check_json_valuekeys(cJSON *json, cJSON *keytext,const char *required_key) {
    keytext = cJSON_GetObjectItem(json, required_key);
    if (cJSON_IsString(keytext) && (keytext->valuestring != NULL)) {
        printf("接收到 %s 的值是 %s\n", required_key, keytext->valuestring);
    }
    else{
        printf("error: cannot find jsonkey: %s\n", required_key);
        return ;
    }
}

// 将十六进制字符串转换为 uint64_t, 用于对数据进行异或
//异或操作：先定义一个内存空间比如：char M1[17]；然后用此函数将两个十六进制字符串转换为uint64_t，然后异或，再用strcmp函数进行比较
uint64_t hex_str_to_uint64(const char *hex_str) {
    return strtoull(hex_str, NULL, 16);
}


/*
    vcs端处理认证信息主题，按以下顺序实现功能：
    1.VCS初步验证（GECU->VCS）、验证MAC值、PGID
    2.VCS应答（VCS->GECU）:生成随机数QCG，发送{PGID，QCG，MAC}
    3.GECU响应（GECU->VCS）:生成QGC，令M_1 = H(QCG || QGC || PW) ⊕ GID，发送{PGID，M_1，QGC，MAC}
    4.VCS验证（VCS->GECU）:检查M_1是否正确，若正确，认证成功，生成M2 = H(QCG || QGC || PW) ⊕ PQCG，发送{PGID，M_2，MAC}
    5.GECU验证（GECU->VCS）:检查M_2是否正确。
*/

void AuthMsg_callback1_GECU2VCS(char* msg){
    printf("***************云端认证网关第一条消息*******************\n");

    // 解析JSON
    cJSON *json = cJSON_Parse(msg);
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return ;
    }

    // 检查格式、验证签名
    int rt = CheckMessage1_gecu2vcs_auth(json);
    if(rt != MSG_CHECK_OK) {
        printf("error in CheckMessage1_gecu2vcs_auth:\n");
        print_errorinfo(rt);
        return ;
    }

    // 解析出PGID_r
    
    cJSON *PGID_r = cJSON_GetObjectItem(json, "PGID");
    check_json_valuekeys(json, PGID_r, "PGID");

    // 获取 GID、PW、PQCG
    cJSON *gid = cJSON_GetObjectItem(configjson, "GID");
    cJSON *PW = cJSON_GetObjectItem(configjson, "PW");
    cJSON *PQCG = cJSON_GetObjectItem(configjson, "PQCG");

    unsigned char MixM_inbuff[1024] = { 0 };
    unsigned char MixM_outbuff[32] ;

    char PGID[32]= {0};

    // 使用 strcat 函数进行字符串拼接（验证拼接哈希值）
    strcat((char*)MixM_inbuff, gid->valuestring);
    strcat((char*)MixM_inbuff, PW->valuestring);
    strcat((char*)MixM_inbuff, PQCG->valuestring);
  
    sha256(MixM_inbuff,strlen((char*)MixM_inbuff),MixM_outbuff);
    ByteToString(MixM_outbuff,PGID,32);

    printf("计算出PGID的值: %s\n", PGID);

    if (strcmp(PGID, PGID_r->valuestring) == 0) {
        printf("PGID 验证成功.\n");
    }
    else{
        printf("PGID 未验证通过，存在问题.\n");
        return ;
    }

    //判断PW与PQCG是否正确(验证异或值)**************************异或操作模板
    char M1[17];
    uint64_t pw_num = hex_str_to_uint64(PW->valuestring);
    uint64_t pqcg_num = hex_str_to_uint64(PQCG->valuestring);
    uint64_t xor_value = pw_num ^ pqcg_num;
    snprintf(M1, sizeof(M1), "%016" PRIX64, xor_value);
    printf("M1: %s\n", M1);
    cJSON *M1_r = cJSON_GetObjectItem(json, "M1");
    printf("M1_r: %s\n", M1_r->valuestring);
    if (strcmp(M1, M1_r->valuestring) == 0) {
        printf("M1验证成功.\n");
    }
    else{
        printf("M1未验证通过，存在问题.\n");
        return ;
    }

    // 开始构建回复的信息(生成随机数QCG，发送{PGID，QCG，MAC})******************挑战应答***********************

    // 生成3s的延时
    sleep(5); 

    // 生成随机数QGC
    unsigned char MixM_inbuff2[512] = { 0 };
    unsigned char MixM_outbuff2[32] ;

    cJSON *QCG = cJSON_GetObjectItem(configjson, "QCG");//这里先进行预置，后期改为随机数
    strcat((char*)MixM_inbuff2, PGID_r->valuestring);
    strcat((char*)MixM_inbuff2, QCG->valuestring);
    sha256(MixM_inbuff2,strlen((char*)MixM_inbuff2),MixM_outbuff2);

    char MAC_PQ[65] = {0};
    ByteToString(MixM_outbuff2,MAC_PQ,32);//设定MAC值长度为16字节
    printf("MAC_PQ: %s\n", MAC_PQ);
    
    //构建消息{PGID，QCG，MAC}
    cJSON *root = NULL;
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "PGID", PGID_r->valuestring);
    cJSON_AddStringToObject(root, "QCG", QCG->valuestring);
    cJSON_AddStringToObject(root, "MAC", MAC_PQ);
    /* declarations */
    char *out_jsonStr = NULL;
    out_jsonStr = cJSON_PrintUnformatted(root);
    
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = out_jsonStr;
    pubmsg.payloadlen = strlen(out_jsonStr);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    
    // 发布消息
    MQTTClient_deliveryToken token;
    MQTTClient_publishMessage(client, "innetwork/vcs2gecu", &pubmsg, &token);
    printf("Waiting for publication of %s\n"
           "on topic %s for client with ClientID: %s\n",
           (char *)pubmsg.payload, "v2g/vcs2gecu", CLIENTID);
    MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);

    free(out_jsonStr); // 释放字符串内存
     // 释放 JSON 对象内存
    cJSON_Delete(root);

    // 释放内存
    cJSON_Delete(json);
    receiveflag++;
}


// 云端认证网关第2条消息
// 计算 H(QCG || QGC || PW)，与 M1⊕GID 比对，确认GECU身份。
// 生成应答消息 M2 = H(QCG || QGC || GID) ⊕ PQCG，发送 {PGID, M2, MAC} 至GECU。
void AuthMsg_callback2_GECU2VCS(char* msg){
    printf("***************云端认证网关第2条消息*******************\n");

    // 解析JSON
    cJSON *json = cJSON_Parse(msg);
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return ;
    }

    // 检查格式、验证签名
    int rt = CheckMessage2_gecu2vcs_auth(json);
    if(rt != MSG_CHECK_OK) {
        printf("error in CheckMessage2_gecu2vcs_auth:\n");
        print_errorinfo(rt);
        return ;
    }

    cJSON *QGC = cJSON_GetObjectItem(json, "QGC");
    cJSON *M_1 = cJSON_GetObjectItem(json, "M1");
    cJSON *QCG = cJSON_GetObjectItem(configjson, "QCG");
    cJSON *PW = cJSON_GetObjectItem(configjson, "PW");
    unsigned char hash_inbuf[1024] = { 0 };
    unsigned char hash_outbuff[32] = { 0 };
    char hash[32]= {0};
    strcat((char*)hash_inbuf, QCG->valuestring);
    strcat((char*)hash_inbuf, QGC->valuestring);
    strcat((char*)hash_inbuf, PW->valuestring);
    
    sha256(hash_inbuf,strlen(hash_inbuf),hash_outbuff);
    ByteToString(hash_outbuff,hash,32);

    cJSON *GID = cJSON_GetObjectItem(configjson, "GID");
    char M1[128];
    uint64_t gid_num = hex_str_to_uint64(GID->valuestring);
    uint64_t hash_num = hex_str_to_uint64(hash);
    uint64_t xor_value = gid_num ^ hash_num;
    snprintf(M1, sizeof(M1), "%016" PRIX64, xor_value);

    printf("M1: %s\n", M1);
    

    if (strcmp(M1, M_1->valuestring) == 0) {
        printf("M_1 验证成功.\n");
    }
    else{
        printf("M_1 未验证通过，存在问题.\n");
        return ;
    }

        // 生成3s的延时
    sleep(3);

    // 生成应答消息 M2 = H(QCG || QGC || GID) ⊕ PQCG，发送 {PGID, M2, MAC} 至GECU。
    /*****哈希*****/
    char hash2[32]= {0};
    unsigned char hash_inbuf2[1024] = { 0 };
    unsigned char hash_outbuff2[32] = { 0 };
    strcat((char*)hash_inbuf2, QCG->valuestring);
    strcat((char*)hash_inbuf2, QGC->valuestring);
    strcat((char*)hash_inbuf2, GID->valuestring);
    sha256(hash_inbuf2,strlen(hash_inbuf2),hash_outbuff2);
    ByteToString(hash_outbuff2,hash2,32);

    /*****异或计算M2*****/
    char M_2[128];
    uint64_t hash2_num = hex_str_to_uint64(hash2);
    uint64_t pqcg_num = hex_str_to_uint64(PW->valuestring);
    uint64_t xor_value2 = hash2_num ^ pqcg_num;
    snprintf(M_2, sizeof(M_2), "%016" PRIX64, xor_value2);

    /*****计算消息MAC*****/
    cJSON *PGID = cJSON_GetObjectItem(json, "PGID");
    char MAC_PM2[32] = {0};
    unsigned char MixM_inbuff[1024] = { 0 };
    unsigned char MixM_outbuff[32] ;
    strcat((char*)MixM_inbuff, PGID->valuestring);
    strcat((char*)MixM_inbuff, M_2);
    sha256(MixM_inbuff,strlen((char*)MixM_inbuff),MixM_outbuff);
    ByteToString(MixM_outbuff,MAC_PM2,32);

    /*******构建JSON消息格式******/
    cJSON *root = NULL;
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "PGID", PGID->valuestring);
    cJSON_AddStringToObject(root, "M2", M_2);
    cJSON_AddStringToObject(root, "MAC", MAC_PM2);
    /* declarations */
    char *out_jsonStr = NULL;
    out_jsonStr = cJSON_PrintUnformatted(root);
    
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = out_jsonStr;
    pubmsg.payloadlen = strlen(out_jsonStr);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    
    // 发布消息
    MQTTClient_deliveryToken token;
    MQTTClient_publishMessage(client, "innetwork/vcs2gecu", &pubmsg, &token);
    printf("Waiting for publication of %s\n"
           "on topic %s for client with ClientID: %s\n",
           (char *)pubmsg.payload, "v2g/vcs2gecu", CLIENTID);
    MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);

    free(out_jsonStr); // 释放字符串内存
     // 释放 JSON 对象内存
    cJSON_Delete(root);

    // 释放内存
    cJSON_Delete(json);
    receiveflag++;
}

// 云端认证网关第3条消息(认证ECU身份)
// 接收{PGID, EID_⊕PQCG, C1, C2, MAC}，C1 = H(EIDi) ⊕ PQGE，C2 = C2 = H(EIDi) ⊕ PQCE
// 计算 H(QCG || QGC || PW)，与 M1⊕GID 比对，确认GECU身份。
// 生成应答消息 M2 = H(QCG || QGC || GID) ⊕ PQCG，发送 {PGID, M2, MAC} 至GECU。
void AuthMsg_callback3_GECU2VCS(char* msg){
    printf("***************云端认证ECU的身份*******************\n");
    // receiveflag++;
    // printf("receiveflag: %d\n", receiveflag);
    // 解析JSON
    cJSON *json = cJSON_Parse(msg);
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return ;
    }

    // 检查格式、验证签名
    int rt = CheckMessage3_gecu2vcs_auth(json);
    
    if(rt != MSG_CHECK_OK) {
        printf("error in CheckMessage3_gecu2vcs_auth:\n");
        print_errorinfo(rt);
        return ;
    }


    //先验证hash亦或参数
    cJSON *PGID = cJSON_GetObjectItem(json, "PGID");
    cJSON *M3 = cJSON_GetObjectItem(json, "M3");
    cJSON *C1 = cJSON_GetObjectItem(json, "C1");

    cJSON *C2 = cJSON_GetObjectItem(json, "C2");

    cJSON *PQGE = cJSON_GetObjectItem(configjson, "PQGE");    
    if (cJSON_IsString(PQGE) && (PQGE->valuestring != NULL)) {
        printf("PQGE: %s\n", PQGE->valuestring);
    }

    cJSON *PQCE = cJSON_GetObjectItem(configjson, "PQCE");
    cJSON *PQCG = cJSON_GetObjectItem(configjson, "PQCG");
    


    //先获取h(EIDi)
    char heidi[64];
    uint64_t m3_num = hex_str_to_uint64(M3->valuestring);
    uint64_t pqcg_num = hex_str_to_uint64(PQCG->valuestring);
    uint64_t xor_value = m3_num ^ pqcg_num;
    snprintf(heidi, sizeof(heidi), "%016" PRIX64, xor_value);

    

    //然后使用h(EIDi)异或C1和C2，是否==PQGE和PQCE
    char pqge[17];

    uint64_t c1_num = hex_str_to_uint64(C1->valuestring);
    uint64_t heidi_num = hex_str_to_uint64(heidi);
    uint64_t xor_value1 = c1_num ^ heidi_num;

    printf("xor_value1: %016" PRIX64 "\n", xor_value1);
    
    snprintf(pqge, sizeof(pqge), "%016" PRIX64, xor_value1);
    // pqge[16] = '\0';
    for (int i = 0; pqge[i]; i++) {
        pqge[i] = tolower(pqge[i]);
    }


    if(strcmp(pqge, PQGE->valuestring) != 0)
    {
        printf("C1验证失败\n");
        return ;
    }
    else{
        printf("C1验证成功\n");
    }
    
    char pqce[64];
    char *pqce1 = (char*)malloc(17);
    uint64_t c2_num = hex_str_to_uint64(C2->valuestring);
    uint64_t xor_value2 = c2_num ^ heidi_num;
    snprintf(pqce, sizeof(pqce), "%016" PRIX64, xor_value2);
    for (int i = 0; pqce[i]; i++) {
        pqce[i] = tolower(pqce[i]);
    }

    if(strcmp(pqce, PQCE->valuestring) != 0)
    {
        printf("C2验证失败\n");
        return ;
    }
    else{
        printf("C2验证成功\n");
        printf("ECU身份验证成功");
    }

    

    //计算发送回去的MAC值({PGID, h(EIDi)⊕PW, MAC})   
        //先算h(EIDi)⊕PW
        cJSON *PW = cJSON_GetObjectItem(configjson, "PW");
        char M_4[32];
        uint64_t pw_num = hex_str_to_uint64(PW->valuestring);
        uint64_t xor_value3 = heidi_num ^ pw_num;
        snprintf(M_4, sizeof(M_4), "%016" PRIX64, xor_value3);
    
    unsigned char hash_inbuf[1024] = { 0 };
    unsigned char hash_outbuff[32] = { 0 };
    char MAC[32]= {0};
    strcat((char*)hash_inbuf, PGID->valuestring);
    strcat((char*)hash_inbuf, M_4);
    
    sha256(hash_inbuf,strlen(hash_inbuf),hash_outbuff);
    ByteToString(hash_outbuff,MAC,32);

        // 生成3s的延时
    sleep(3);


    /*******构建JSON消息格式******/
    cJSON *root = NULL;
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "PGID", PGID->valuestring);
    cJSON_AddStringToObject(root, "M4", M_4);
    cJSON_AddStringToObject(root, "MAC", MAC);
    /* declarations */
    char *out_jsonStr = NULL;
    out_jsonStr = cJSON_PrintUnformatted(root);
    
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = out_jsonStr;
    pubmsg.payloadlen = strlen(out_jsonStr);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    
    // 发布消息
    MQTTClient_deliveryToken token;
    MQTTClient_publishMessage(client, "innetwork/vcs2gecu", &pubmsg, &token);
    printf("Waiting for publication of %s\n"
           "on topic %s for client with ClientID: %s\n",
           (char *)pubmsg.payload, "v2g/vcs2gecu", CLIENTID);
    MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);

    free(out_jsonStr); // 释放字符串内存
     // 释放 JSON 对象内存
    cJSON_Delete(root);

    // 释放内存
    cJSON_Delete(json);
    receiveflag++;
}

void read_json_file(const char *filename) {
    // 读取文件内容
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = malloc(length + 1);
    fread(data, 1, length, file);
    fclose(file);
    data[length] = '\0'; // 确保字符串以 NULL 结尾

    // 解析 JSON
    configjson = cJSON_Parse(data);
    if (!configjson) {
        printf("Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        free(data);
        return;
    }

    // 读取数据
    cJSON *address = cJSON_GetObjectItem(configjson, "address");
    cJSON *clientid = cJSON_GetObjectItem(configjson, "clientid");
    cJSON *topic = cJSON_GetObjectItem(configjson, "topic");
    cJSON *qos = cJSON_GetObjectItem(configjson, "qos");

    

    // 打印数据
    if (cJSON_IsString(address) && (address->valuestring != NULL)) {
        printf("address: %s\n", address->valuestring);
        ADDRESS = address->valuestring;
    }
    if (cJSON_IsNumber(qos) ) {
        printf("qos: %d\n", qos->valueint);
        QOS = qos->valueint;
    }
    if (cJSON_IsString(clientid) && (clientid->valuestring != NULL)) {
        printf("clientid: %s\n", clientid->valuestring);
        CLIENTID = clientid->valuestring;
    }

    if (cJSON_IsString(topic) && (topic->valuestring != NULL)) {
        printf("topic: %s\n", topic->valuestring);
        TOPIC = topic->valuestring;
    }
    

    // 释放内存
    // cJSON_Delete(json);
    // free(data);
}

void delivered(void *context, MQTTClient_deliveryToken dt) {
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}




int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
    printf("Message arrived on topic: %s\n", topicName);
    printf("Message content: %.*s\n", message->payloadlen, (char *)message->payload);

    // 打印 message 的地址
    // printf("Message address: %p\n", (void *)message);
    if(receiveflag == 0){
        AuthMsg_callback1_GECU2VCS((char *)message->payload);
        // msgarrvd_handler(message);

        MQTTClient_freeMessage(&message);
        MQTTClient_free(topicName);
    

    }
    else if(receiveflag == 1){
        AuthMsg_callback2_GECU2VCS((char *)message->payload);
        // msgarrvd_handler(message);

        MQTTClient_freeMessage(&message);
        MQTTClient_free(topicName);

    }
    else if(receiveflag == 2 || receiveflag == 3 || receiveflag == 4 || receiveflag == 5){
        AuthMsg_callback3_GECU2VCS((char *)message->payload);
        // msgarrvd_handler(message);

        MQTTClient_freeMessage(&message);
        MQTTClient_free(topicName);
  

    }
    return 1;
}

void connlost(void *context, char *cause) {
    printf("\nConnection lost\n");
    printf("Cause: %s\n", cause);
}


int main(int argc, char* argv[]) {

    read_json_file("VCSconfig.json");    
    

    MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 0;
    conn_opts.password = "123456";
    conn_opts.username = "VCS";

    MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered) ;


    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    MQTTClient_subscribe(client, TOPIC, QOS);

    
    getchar();

    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return rc;
}

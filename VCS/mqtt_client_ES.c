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

// 新增: 用于获取IP地址的头文件
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h> // 修正: 添加此头文件以定义 NI_MAXHOST


// 配置文件信息
static cJSON *configjson;

// 用于存储会话中从GECU收到的动态QGC
char session_qgc[33] = {0};

int ECU_flag = 0; // 标志位，标志是否已经认证通过

char* ADDRESS = NULL;
char* CLIENTID = NULL;
char* TOPIC = NULL;
int QOS = 0;

int receiveflag = 0;
char qcg_random[17];
cJSON *QGC = NULL;
char qgc[256]; // Allocate sufficient space for the string

// #define QOS         2
#define TIMEOUT     10000L

volatile MQTTClient_deliveryToken deliveredtoken;
MQTTClient client;
MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
int rc;

/**
 * @brief 获取本机在局域网中的IPv4地址
 * @return 返回IP地址字符串，如果失败则返回NULL
 */
char* get_local_ip() {
    static char ip_buffer[INET_ADDRSTRLEN]; // 静态缓冲区，用于存储IP地址字符串
    struct ifaddrs *ifaddr, *ifa;
    int family;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    // 遍历所有网络接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        // 我们只关心IPv4地址，并排除本地回环接口("lo")
        if (family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip_buffer, sizeof(ip_buffer));
            freeifaddrs(ifaddr); // 释放内存
            return ip_buffer; // 找到第一个符合条件的IP地址后就返回
        }
    }

    freeifaddrs(ifaddr); // 释放内存
    return NULL; // 如果没有找到非回环的IPv4地址
}

// 辅助函数：将单个十六进制字符转换为整数值
int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 辅助函数：将十六进制字符串转换为字节数组
void hex_to_bytes(unsigned char* dest, const char* src, int byte_len) {
    for (int i = 0; i < byte_len; i++) {
        int high = hex_char_to_int(src[i * 2]);
        int low = hex_char_to_int(src[i * 2 + 1]);
        if (high != -1 && low != -1) {
            dest[i] = (high << 4) | low;
        } else {
            dest[i] = 0; // 错误处理
        }
    }
}

// 辅助函数：将字节数组转换为十六进制字符串
void bytes_to_hex(char* dest, const unsigned char* src, int byte_len) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(dest + i * 2, "%02x", src[i]);
    }
}


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
    sleep(3); 

     // 动态随机生成QCG
    
    generate_random_string(qcg_random, 16);
    printf("Generated QCG: %s\n", qcg_random);

    unsigned char MixM_inbuff2[512] = { 0 };
    unsigned char MixM_outbuff2[32] ;

    strcat((char*)MixM_inbuff2, PGID_r->valuestring);
    strcat((char*)MixM_inbuff2, qcg_random);
    sha256(MixM_inbuff2,strlen((char*)MixM_inbuff2),MixM_outbuff2);

    char MAC_PQ[65] = {0};
    ByteToString(MixM_outbuff2,MAC_PQ,32);//设定MAC值长度为16字节
    printf("MAC_PQ: %s\n", MAC_PQ);
    
    //构建消息{PGID，QCG，MAC}
    cJSON *root = NULL;
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "PGID", PGID_r->valuestring);
    cJSON_AddStringToObject(root, "QCG", qcg_random);
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

    

    QGC = cJSON_GetObjectItem(json, "QGC");
    strcpy(qgc, QGC->valuestring); // Copy the string into the allocated array
    printf("QGC from message: %s\n", qgc);
    cJSON *M_1 = cJSON_GetObjectItem(json, "M1");

    cJSON *PW = cJSON_GetObjectItem(configjson, "PW");

    

    unsigned char hash_inbuf[1024] = { 0 };
    unsigned char hash_outbuff[32] = { 0 };
    char hash[32]= {0};

    strcat((char*)hash_inbuf, qcg_random);
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

        if (cJSON_IsString(QGC) && QGC->valuestring != NULL) {
        strncpy(session_qgc, QGC->valuestring, sizeof(session_qgc) - 1);
        printf("  会话QGC已存储: %s\n", session_qgc);
    }

        // 生成3s的延时
    sleep(3);

    // 生成应答消息 M2 = H(QCG || QGC || GID) ⊕ PQCG，发送 {PGID, M2, MAC} 至GECU。
    /*****哈希*****/
    char hash2[32]= {0};
    unsigned char hash_inbuf2[1024] = { 0 };
    unsigned char hash_outbuff2[32] = { 0 };
    strcat((char*)hash_inbuf2, qcg_random);
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

    // sleep(3);

    // pubmsg.payload = "1111111111";
    // pubmsg.payloadlen = strlen("1111111111");
    // pubmsg.qos = QOS;
    // pubmsg.retained = 0;
    // MQTTClient_publishMessage(client, "innetwork/vcs2gecu", &pubmsg, &token);
    // printf("Waiting for publication of %s\n"
    //        "on topic %s for client with ClientID: %s\n",
    //        (char *)pubmsg.payload, "v2g/vcs2gecu", CLIENTID);
    // MQTTClient_waitForCompletion(client, token, TIMEOUT);


    receiveflag++;
}

// 云端认证网关第3条消息(认证ECU身份)
// 接收{PGID, H(EIDi)⊕PQCG, C1, MAC}，C1 = H(EIDi) ⊕ QGC
// 计算 H(QCG || QGC || PW)，与 M1⊕GID 比对，确认GECU身份。
// 生成应答消息 M2 = H(QCG || QGC || GID) ⊕ PQCG，发送 {PGID, M2, MAC} 至GECU。
void AuthMsg_callback3_GECU2VCS(char* msg){
    printf("***************云端认证ECU的身份*******************\n");
    
    printf("*************** VCS: Authenticating ECU Identity *******************\n");

    cJSON *json = cJSON_Parse(msg);
    if (!json) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return;
    }

    // 1. 检查消息格式和MAC
    // 注意：需要修改 CheckMessage3_gecu2vcs_auth 以匹配新的格式
    int rt = CheckMessage3_gecu2vcs_auth(json);
    if(rt != MSG_CHECK_OK) {
        printf("error in CheckMessage3_gecu2vcs_auth:\n");
        print_errorinfo(rt);
        cJSON_Delete(json);
        return;
    }

    cJSON *PGID = cJSON_GetObjectItem(json, "PGID");
    cJSON *M3 = cJSON_GetObjectItem(json, "M3");
    cJSON *C1 = cJSON_GetObjectItem(json, "C1");

// 2. 修正: 使用字节级异或反解 H(EIDi) 的前16字节
    unsigned char m3_bytes[16];
    unsigned char pqcg_bytes[16];
    unsigned char recovered_heidi_bytes_part[16]; // H(EIDi)的前16字节
    char recovered_heidi_hex_part[33] = {0};

    hex_to_bytes(m3_bytes, M3->valuestring, 16);
    cJSON *PQCG_json = cJSON_GetObjectItem(configjson, "PQCG");
    hex_to_bytes(pqcg_bytes, PQCG_json->valuestring, 16);
    printf("  Received M3:         %s\n", M3->valuestring);
    printf("  PQCG from config:    %s\n", PQCG_json->valuestring);

    for(int i = 0; i < 16; i++) {
        recovered_heidi_bytes_part[i] = m3_bytes[i] ^ pqcg_bytes[i];
    }
    
    bytes_to_hex(recovered_heidi_hex_part, recovered_heidi_bytes_part, 16);
    printf("  Recovered H(EIDi) Part (16 bytes): %s\n", recovered_heidi_hex_part);


    // 3. 修正: 使用字节级异或验证 C1
    unsigned char qgc_bytes[16];
    unsigned char calculated_c1_bytes[16];
    char calculated_c1_hex[33] = {0};
    
    // 修正 #3: 使用存储的会话QGC，而不是从配置文件读取
    if (strlen(session_qgc) == 0) {
        printf("  [错误]: 未能获取到会话QGC, 无法验证C1.\n");
        cJSON_Delete(json);
        return;
    }
    hex_to_bytes(qgc_bytes, session_qgc, 16);

    for(int i = 0; i < 16; i++) {
        calculated_c1_bytes[i] = recovered_heidi_bytes_part[i] ^ qgc_bytes[i];
    }
    bytes_to_hex(calculated_c1_hex, calculated_c1_bytes, 16);

    printf("  Received C1:         %s\n", C1->valuestring);
    printf("  Calculated C1:       %s\n", calculated_c1_hex);

    if (strcasecmp(calculated_c1_hex, C1->valuestring) != 0)
    {
        printf("  C1 verification FAILED. ECU is NOT authentic.\n");
        cJSON_Delete(json);
        return;
    }
    else
    {
        ECU_flag ++;
        printf("  C1 verification SUCCESS. ECU is authentic.\n");
    }
// 4. 构建并发送成功响应
    char status_msg[] = "SUCCESS";
    unsigned char hash_in_mac[1024] = { 0 };
    char MAC_response[65] = {0};

    // 注意: GECU侧需要H(EIDi)来识别是哪个ECU的响应，但VCS只恢复了部分哈希
    // 为了让GECU能匹配，我们这里返回恢复出的部分哈希
    strcat((char*)hash_in_mac, PGID->valuestring);
    strcat((char*)hash_in_mac, recovered_heidi_hex_part); 
    strcat((char*)hash_in_mac, status_msg);

    unsigned char hash_outbuff[32];
    sha256(hash_in_mac, strlen((char*)hash_in_mac), hash_outbuff);
    ByteToString(hash_outbuff, MAC_response, 32);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "PGID", PGID->valuestring);
    cJSON_AddStringToObject(root, "H_EIDi_part", recovered_heidi_hex_part); // 返回部分 H(EIDi) 以供识别
    cJSON_AddStringToObject(root, "status", status_msg);
    cJSON_AddStringToObject(root, "MAC", MAC_response);

    sleep(3);

    char *out_jsonStr = cJSON_PrintUnformatted(root);

    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = out_jsonStr;
    pubmsg.payloadlen = strlen(out_jsonStr);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;

    MQTTClient_deliveryToken token;
    MQTTClient_publishMessage(client, "innetwork/vcs2gecu", &pubmsg, &token);
    printf("  Sent SUCCESS response to GECU: %s\n", out_jsonStr);
    MQTTClient_waitForCompletion(client, token, TIMEOUT);

    free(out_jsonStr);
    cJSON_Delete(root);
    cJSON_Delete(json);
    receiveflag++;
    if(ECU_flag < 5){
        printf("  ECU认证成功，当前已认证通过的ECU数量: %d\n", ECU_flag);
    }
    else{
        printf("  ECU认证失败，当前已认证通过的ECU数量: %d\n", ECU_flag);
    }
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
    //cJSON *address = cJSON_GetObjectItem(configjson, "address");
    cJSON *clientid = cJSON_GetObjectItem(configjson, "clientid");
    cJSON *topic = cJSON_GetObjectItem(configjson, "topic");
    cJSON *qos = cJSON_GetObjectItem(configjson, "qos");

    

    // 打印数据
    // if (cJSON_IsString(address) && (address->valuestring != NULL)) {
    //     printf("address: %s\n", address->valuestring);
    //     ADDRESS = address->valuestring;
    // }
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

    // 初始化随机数种子
    srand(time(NULL));
    read_json_file("VCSconfig.json");    
    
        // 动态获取本机IP地址
    char* local_ip = get_local_ip();
    static char broker_address[100]; // 使用静态数组存储地址

    if (local_ip != NULL) {
        // 构建完整的 MQTT Broker 地址 (tcp://ip:port)
        snprintf(broker_address, sizeof(broker_address), "tcp://%s:1883", local_ip);
        ADDRESS = broker_address;
        printf("成功获取本机IP, MQTT Broker地址设置为: %s\n", ADDRESS);
    } else {
        printf("警告: 无法自动获取本机IP地址, 将尝试使用配置文件中的地址。\n");
        // 如果获取失败，则回退到使用配置文件中的地址
        cJSON* address_json = cJSON_GetObjectItem(configjson, "address");
        if (cJSON_IsString(address_json) && (address_json->valuestring != NULL)) {
            ADDRESS = address_json->valuestring;
             printf("使用配置文件中的地址: %s\n", ADDRESS);
        } else {
            fprintf(stderr, "错误: 配置文件中也未找到地址, 程序无法启动。\n");
            exit(EXIT_FAILURE);
        }
    }
    

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

    printf("VCS已启动，等待来自GECU的消息...\n 按下回车键退出程序。\n");
    getchar();

    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    cJSON_Delete(configjson);
    return rc;
}

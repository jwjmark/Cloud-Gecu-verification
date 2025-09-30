#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h> // 新增: 用于随机数生成
#include <time.h>   // 新增: 用于随机数种子
#include "./SYSTEM/sys/sys.h"
#include "./SYSTEM/usart/usart.h"
#include "./SYSTEM/delay/delay.h"
#include "./BSP/LED/led.h"
#include "./ESP8266/esp8266.h"
#include "./SM4/sm4.h"
#include "./SHA256/sha256.h"
#include "./CJSON/cJSON.h"  
#include "./BYTE2STRING/byte2string.h"
#include "./CAN/can.h" 
#include "./MESSAGECHECK/messageCheck.h"
#include "./KEY/key.h" 



#define KEYTAG "cs001key"
#define CSID "cs001"
#define time_buffer "2025.01.08/15:25.08"
#define CSID "cs001"

// --- 自定义参数 ---
#define NUM_ECUS 4
const char* ecu_ids[NUM_ECUS] = {"ecu001", "ecu002", "ecu003", "ecu004"};
unsigned char* PQGE[33] = {0}; // 新增: 用于ECU认证的预共享密钥
unsigned char QGC[33] = {0};

volatile AuthState g_auth_state = STATE_GECU_VCS_HANDSHAKE;
int current_ecu_index = 0;
// --------------------

extern cJSON *json_es2cs;

// 函数声明
void send_ecu_auth_request(const char* eid);
void generate_random_key(unsigned char* key, int byte_length); // 新增: 随机密钥生成函数声明


int main(void)
{
    char *out_jsonStr = NULL;
    int retval=0;
    int state = 0;
	extern int msg_len;
	extern uint8_t msg_body[128];
	extern uint16_t receive_count;
	extern unsigned char receive_buf[];
	extern uint16_t receive_finish;
	
	extern uint8_t IRQflag;      // CAN:数据接收完成标志位  //CAN 始
	extern uint8_t data_buffer[MAX_DATA_BUFFER_SIZE];
	extern uint8_t buffer_index; // 当前数据写入位置
	uint8_t canbuf[]={12, 12, 12, 21, 21, 21, 21, 21, 31, 31, 31,31,41, 41, 41, 41};
    int btest = strlen((char *)canbuf);
    uint8_t rxlen = 0;
    uint8_t res;
    uint8_t mode = 0; /* CAN工作模式: 0,普通模式; 1,环回模式 */
    char received_json_str[200];
    uint8_t rxbuff[16];          							//CAN 尾
    
	
    HAL_Init();                                 /* 初始化HAL库 */
    sys_stm32_clock_init(336, 8, 2, 7);         /* 设置时钟,168Mhz */
    delay_init(168);                            /* 延时初始化 */
    led_init();                                 /* 初始化LED */
	delay_ms(1000);
	usart_init(115200);
	usart3_init(115200);
	key_init();
	can_init(CAN_SJW_1TQ, CAN_BS2_6TQ, CAN_BS1_7TQ, 6, CAN_MODE_NORMAL);  /* CAN初始化, 正常模式, 波特率500Kbps */
	esp8266_init();

    
    // 初始化随机数种子
    srand(256);

    // 随机生成 PQGE
    generate_random_key(PQGE, 16);
    printf("Generated PQGE: %s\n", PQGE);

    sm4_context My_sm4_context;
	unsigned char MY_key[16];
    // 随机生成 MY_key (SM4密钥)
    for(int i=0; i<16; i++)
    {
        MY_key[i] = rand() % 256;
    }

    /********************身份认证第一次发送挑战*************************/
    //生成消息：{PGID, PW⊕PQ_CG, MAC, T}
    
    unsigned char hash_in[1024];
    strcat((char*)hash_in , GID);
    strcat((char*)hash_in , PW);
    strcat((char*)hash_in , PQCG);
    
    memset(PGID , 0 , sizeof(PGID));
    char *result = Sha256_auth(hash_in);
    if (result != NULL) 
    {
        strncpy(PGID, result, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
        PGID[64] = '\0';  // 确保字符串以 '\0' 结束
    }
    
    
    //生成PW⊕PQ_CG
    char Mix_m1[17] = {0};
    uint64_t pw_num = strtoull((char*)PW , NULL , 16);
    uint64_t pqcg_num = strtoull((char*)PQCG , NULL , 16);
    uint64_t xor_value = pw_num ^ pqcg_num;
    snprintf(Mix_m1, sizeof(Mix_m1), "%016" PRIX64, xor_value);
    Mix_m1[16] = '\0';
    
    //整条消息的MAC值生成
    memset(hash_in , 0 ,sizeof(hash_in));
    strcat((char*)hash_in, PGID);
    strcat((char*)hash_in, Mix_m1);
    char MAC1[65] = {0};
    char *result2 = Sha256_auth(hash_in);
    if (result2 != NULL) 
    {
        strncpy(MAC1, result2, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
        MAC1[64] = '\0';  // 确保字符串以 '\0' 结束
    }
    
    //构建JSON串
    cJSON *root1 = NULL;                              
    root1 = cJSON_CreateObject();                    //创建JSON对象
    
    cJSON_AddStringToObject(root1, "PGID", PGID);
    cJSON_AddStringToObject(root1, "M1", Mix_m1);
    cJSON_AddStringToObject(root1, "MAC", MAC1);
    
    extern    char *out;
    extern    char *escaped_out1;
    out = cJSON_PrintUnformatted(root1);
    escaped_out1 = add_escape_characters(out);
    printf("\n");
    esp8266_send_msg();
//    free(root1);


	
    while(1)
    {
        delay_ms(100);
        // 动态随机生成QGC
        
        

		if(esp8266_receive_msg() == 0)     //esp8266使用MQTT订阅消息
		{
            printf("\n 111111111112323232323 \n");
            if(esp_rxflag == 0)
            {
                // 检查消息格式是否正确
                int rt = CheckMessage_es2cs_auth(json_es2cs);
                if ( rt!= MSG_CHECK_OK) 
                {
                    printf("Error CheckMessage_vcs2gecu_auth: \n");
                    print_errorinfo(rt);
                    return 1;
                }
                else if ( rt == MSG_CHECK_OK) 
                {
                    retval = 0;
                }
                memset(receive_buf,0x00,receive_count);
                receive_count = 0;
                
                cJSON *qcg = cJSON_GetObjectItem(json_es2cs, "QCG");
                
                char *QCG = qcg->valuestring;
                generate_random_key(QGC, 16);
                printf("Generated QGC: %s\n", QGC);
                
                //生成哈希组合
                unsigned char hash_in[1024];
                char Mix1[65] = {0};
                strcat((char*)hash_in, qcg->valuestring);
                strcat((char*)hash_in, (char*)QGC);
                strcat((char*)hash_in, PW);
                char *result = Sha256_auth(hash_in);
                if(result != NULL)
                {
                    strncpy(Mix1, result, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
                    Mix1[64] = '\0';  // 确保字符串以 '\0' 结束    
                }
                //生成异或组合消息M1
                char M1[17] = {0};
                uint64_t mix1_num = strtoull((char*)Mix1 , NULL , 16);
                uint64_t gid_num = strtoull((char*)GID, NULL, 16);
                uint64_t xor_value = mix1_num ^ gid_num;
                snprintf(M1, sizeof(M1), "%016" PRIX64, xor_value);
                M1[16] = '\0';
                
                char pgid_c[10]= {0};
                memcpy(pgid_c , PGID , 10);
                
                //生成消息认证码MAC
                char MAC[65] = {0};
                memset(hash_in , 0 , sizeof(hash_in));
                strcat((char*)hash_in, pgid_c);
                strcat((char*)hash_in, M1);
                strcat((char*)hash_in, (char*)QGC);
                char *result2 = Sha256_auth(hash_in);
                if(result2 != NULL)
                {
                    strncpy(MAC, result2, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
                    MAC[64] = '\0';  // 确保字符串以 '\0' 结束    
                }          
                
                // 开始构建回复的信息
                cJSON *root = NULL;
                /* Our "Video" datatype: */
                root = cJSON_CreateObject();
                cJSON_AddStringToObject(root, "PGID", pgid_c);
                cJSON_AddStringToObject(root, "M1", M1);
                cJSON_AddStringToObject(root, "QGC", (char*)QGC);
                cJSON_AddStringToObject(root, "MAC", MAC);

                out_jsonStr = cJSON_PrintUnformatted(root);	
                escaped_out1 = add_escape_characters(out_jsonStr);
                delay_ms(2000);
                printf("\n");
                esp8266_send_msg();
    //            free(json_es2cs);
                esp_rxflag++;
            }
            else if(esp_rxflag == 1)
            {
                // 检查消息格式是否正确
                int rt = CheckMessage_es2cs_auth(json_es2cs);
                if ( rt!= MSG_CHECK_OK) 
                {
                    printf("Error CheckMessage_vcs2gecu_auth: \n");
                    print_errorinfo(rt);
                    return 1;
                }
                else if ( rt == MSG_CHECK_OK) 
                {
                    retval = 0;
                }
                memset(receive_buf,0x00,receive_count);
                receive_count = 0;
                
                //生成哈希组合
                unsigned char hash_in[1024];
                char Mix1[65] = {0};
                strcat((char*)hash_in, QCG);
                strcat((char*)hash_in, (char*)QGC);
                strcat((char*)hash_in, GID);
                char *result = Sha256_auth(hash_in);
                if(result != NULL)
                {
                    strncpy(Mix1, result, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
                    Mix1[64] = '\0';  // 确保字符串以 '\0' 结束    
                }
                //生成异或组合消息M1
                char M_2[17] = {0};
                uint64_t mix1_num = strtoull((char*)Mix1 , NULL , 16);
                uint64_t pqcg_num = strtoull((char*)PQCG, NULL, 16);
                uint64_t xor_value = mix1_num ^ pqcg_num;
                snprintf(M_2, sizeof(M_2), "%016" PRIX64, xor_value);
                M_2[16] = '\0';
                char* a = PQCG;
                
                cJSON *m2 = cJSON_GetObjectItem(json_es2cs, "M2");
                
                if(strcmp(M_2, m2->valuestring) != 0)
                {
                    delay_ms(500);
                    printf("Certificate success, now sending third authentication message.\n");
                    g_auth_state = STATE_GECU_VCS_AUTH_SUCCESS; // 更新状态，触发ECU认证

                }
                else
                {
                    printf("certificate fail\n");
                }
    //            free(json_es2cs);
                esp_rxflag++ ;
                
            }
            else if (esp_rxflag >= 2) // 处理ECU认证的响应
            {
                if (g_auth_state == STATE_ECU_AUTH_PENDING)
                {
                    printf("--- Received VCS response for ECU: %s ---\n", ecu_ids[current_ecu_index]);

                    cJSON *status = cJSON_GetObjectItem(json_es2cs, "status");
                    if (cJSON_IsString(status) && (strcmp(status->valuestring, "SUCCESS") == 0))
                    {
                        printf("  ECU authentication SUCCESS.\n");
                        // 模拟将PQGE发送给ECU
                        printf("  Simulating: Sending PQGE (%s) to %s.\n", PQGE, ecu_ids[current_ecu_index]);

                        current_ecu_index++; // 准备认证下一个ECU
                        g_auth_state = STATE_ECU_AUTH_START; // 返回起始状态以认证下一个
                    }
                    else
                    {
                        printf("  ECU authentication FAILED. Stopping.\n");
                        // 在这里可以决定是停止还是重试
                        while(1);
                    }
                }
    //            free(json_es2cs);
                esp_rxflag++; // 增加计数
            }
            
            // 2. GECU-VCS认证成功后，开始ECU的轮询认证
            if (g_auth_state == STATE_GECU_VCS_AUTH_SUCCESS)
            {
                 g_auth_state = STATE_ECU_AUTH_START; // 防止重复进入
                 current_ecu_index = 0;
                 printf("\n\n--- GECU-VCS Handshake Complete. Starting ECU Authentication Loop ---\n");
            }

            // 3. 发送ECU认证请求
            if (g_auth_state == STATE_ECU_AUTH_START)
            {
                if (current_ecu_index < NUM_ECUS)
                {
                    printf("\n--- Authenticating ECU #%d: %s ---\n", current_ecu_index + 1, ecu_ids[current_ecu_index]);
                    send_ecu_auth_request(ecu_ids[current_ecu_index]);
                    g_auth_state = STATE_ECU_AUTH_PENDING; // 等待VCS的回应

                }
                else
                {
                    printf("\n\n--- All ECUs have been authenticated successfully. ---\n");
                    g_auth_state = STATE_GECU_VCS_AUTH_SUCCESS; // 可以回到就绪状态或停止
                    // 在这里可以无线循环，或者重置 current_ecu_index 来重新开始
    //                    while(1);
                }
            }
		}
        
         

    }
}	
 
/**
 * @brief 构建并发送ECU身份认证请求
 * @param eid 要认证的ECU ID
 */
void send_ecu_auth_request(const char* eid)
{
    char pgid_s[10] = {0};
    memcpy(pgid_s , PGID , 10);
    
    // 1. 计算 H(EIDi)
    char heidi[65] = {0};
    char *result_heidi = Sha256_auth((unsigned char*)eid);
    if (result_heidi != NULL) {
        strncpy(heidi, result_heidi, 64);
    }
    printf("  H(EIDi): %s\n", heidi);

    // 2. 计算 M3 = H(EIDi) ⊕ PQCG
    char M3[17] = {0};
    uint64_t heidi_num = strtoull(heidi, NULL, 16);
    uint64_t pqcg_num = strtoull((char*)PQCG, NULL, 16);
    snprintf(M3, sizeof(M3), "%016" PRIX64, heidi_num ^ pqcg_num);
    printf("  M3 (H(EIDi) XOR PQCG): %s\n", M3);

    // 3. 计算 C1 = H(EIDi) ⊕ QGC
    char C1[17] = {0};
    uint64_t qgc_num = strtoull((char*)QGC, NULL, 16);
    snprintf(C1, sizeof(C1), "%016" PRIX64, heidi_num ^ qgc_num);
    printf("  C1 (H(EIDi) XOR qgc): %s\n", C1);

    // 4. 计算 MAC = H(PGID || M3 || C1)
    unsigned char hash_in_mac[1024] = {0};
    strcat((char*)hash_in_mac, pgid_s);
    strcat((char*)hash_in_mac, M3);
    strcat((char*)hash_in_mac, C1);
    char MAC[65] = {0};
    
    char *mac_result = Sha256_auth(hash_in_mac);
    if (mac_result != NULL) {
        strncpy(MAC, mac_result, 64);
    }
    printf("  MAC: %s\n", MAC);

    // 5. 构建JSON并发送
    cJSON *root_ecu_auth = cJSON_CreateObject();
    cJSON_AddStringToObject(root_ecu_auth, "PGID", pgid_s);
    cJSON_AddStringToObject(root_ecu_auth, "M3", M3);
    cJSON_AddStringToObject(root_ecu_auth, "C1", C1);
    cJSON_AddStringToObject(root_ecu_auth, "MAC", MAC);

    extern char *out;
    extern char *escaped_out1;
    out = cJSON_PrintUnformatted(root_ecu_auth);
    escaped_out1 = add_escape_characters(out);
    printf("  Sending to VCS: %s\n", out);
    esp8266_send_msg();

//    cJSON_Delete(root_ecu_auth);
//    free(out);
}

/**
 * @brief 生成指定字节长度的随机十六进制字符串密钥
 * @param key 用于存储密钥的缓冲区
 * @param byte_length 密钥的字节长度 (例如, 16字节)
 */
void generate_random_key(unsigned char* key, int byte_length)
{
    int i;
    for (i = 0; i < byte_length * 2; i++)
    {
        int random_value = rand() % 16;
        if (random_value < 10)
        {
            key[i] = '0' + random_value;
        }
        else
        {
            key[i] = 'a' + (random_value - 10);
        }
    }
    key[byte_length * 2] = '\0';
}


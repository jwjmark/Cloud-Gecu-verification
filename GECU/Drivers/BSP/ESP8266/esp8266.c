#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "./ESP8266/esp8266.h"
#include "usart.h"
#include "./SYSTEM/usart/usart.h"
//#include "./CORE_JSON/core_json.h"
#include "delay.h"
#include "./LED/led.h"
#include "./CJSON/cJSON.h"  
#include "./MESSAGECHECK/messageCheck.h"
#include "./CAN/can.h"  
#include "./SM4/sm4.h"  
#include "./BYTE2STRING/byte2string.h"
#include "./MALLOC/malloc.h"

/*
*************************************
宏定义
*************************************
*/
#define WIFI_SSID        "test2"
#define WIFI_PASSWD      "88888888"


#define MQTT_CLIENT_ID   "client1"   
#define MQTT_USER_NAME   "GECU"
#define MQTT_PASSWD      "123456"
#define BROKER_ASDDRESS  "192.168.235.170"
#define SUB_TOPIC        "innetwork/vcs2gecu"
#define PUB_TOPIC        "innetwork/gecu2vcs"
//#define JSON_FORMAT      "{\\\"msg\\\":\\\"hello\\\"\\\,\\\"mvg\\\":\\\"hi\\\"\\\,\\\"m1g\\\":\\\"AKDKSDAKJAJDSIKAJDIAJD\\\"\\\,\\\"m2g\\\":\\\"123\\\"\\\,\\\"m3\\\":\\\"XAJHNDJWHDNJW\\\"}"
//#define JSON_FORMAT      "{\\\"msg\\\":\\\"hello\\\"\\\,\\\"mvg\\\":\\\"hi\\\"\\\,\\\"m1g\\\":\\\"Awefwefwefwefrwe\\\"\\\,\\\"m2g\\\":\\\"hgdfgdfbdfewffwefwefefefbdfbdfb\\\"}"
#define JSON_FORMAT      "{\\\"M5\\\":\\\"Msgduykykykytuyuyukyukyukyukyututyuk\\\"}"
//#define JSON_FORMAT1      "{\\\"keytag\\\":\\\"ev001key1\\\"\\,\\\"data\\\":\\\"7AD6B6140B33EF4AE2CDD7B58FDA28FE\\\"\\,\\\"timestap\\\":\\\"2025.01.08/15:25.07\\\"\\,\\\"digest\\\":\\\"41D7261B9A360EBADF09A9C7A54EFCB4A3BB4231C0ED3E9B6A54E608C82F5E7D\\\"}"
#define JSON_FORMAT2      "{\\\"M5\\\":\\\"Msgduykykykytuyuyukyukyukyukyututyuk\\\"}"
//#define JSON_FORMAT      "9A4F676266BA7206249BBE502B0AD1A652E7669A1C7B7617116FC0692CB144872412341333333333333333333333335454545624632462"
/*
*************************************
宏定义
*************************************
*/
/*
*************************************
变量声明
*************************************
*/

extern unsigned char receive_buf[];   //串口3接收缓存数组
extern uint16_t receive_count;	      //串口3接收数据计数器
extern uint16_t receive_finish;	    //串口3接收结束标志位 

char PGID[65] = {0};  // 定义并初始化为空字符串
char *QCG = 0 ;
char *QGC = 0;

/*
*************************************
变量定义
*************************************
*/



int esp_rxflag = 0;  //0:身份认证第一次接收：{{PGID, QCG, MAC}; 
                     //1:身份认证第二次接收：({{PGID, M2, MAC});  （M2 =  H(QCG || QGC || GID) ⊕ PQCG）
                     //2:身份认证第三次接收：
int msg_len=0;
unsigned char msg_body[512] = {0};
int msg_len_global=0;
uint8_t msg_body_global[128] = {0};

char *out = NULL;                   //串口3发送的Json数据 
char *escaped_out = NULL;           //为串口3发送的Json数据添加转义字符
char *escaped_out1 = NULL; 
char *escaped_out2 = NULL; 

/**
  * @brief          串口3数据接收清0函数
  * @param[in]      len:清空的数据长度
  * @retval         none
  */
void uart3_receiver_clear(uint16_t len)	
{
	memset(receive_buf,0x00,len);      //receive_buf[]数组数据清0
	receive_count = 0;                 //receive_buf[]数组清空数据长度
	receive_finish = 0;                //接收结束标志位
}
/**
  * @brief          esp8266发送命令函数
  * @param[in]      cmd:发送的命令,len:命令的长度,rec_data:期望接收数据
  * @retval         none
  */
uint8_t esp8266_send_cmd(unsigned char *cmd,unsigned char len,char *rec_data)	
{
	unsigned char retval =0;
	HAL_UART_Transmit(&g_uart3_handle, cmd, len, 1000);	 
	delay_ms(2000);	
	if(strstr((const char*)receive_buf, rec_data))  
	{
		uart3_receiver_clear(receive_count);
		retval = 0;
	}
	else
	{
		retval = 1;		
	}
	return retval;
}
/**
  * @brief          esp8266配置wifi网络
  * @param[in]      none
  * @retval         网络配置成功返回0,否则返回1
  */
uint8_t esp8266_config_network(void)
{
	uint8_t retval =0;
	HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)"AT+CWJAP=\""WIFI_SSID"\",\""WIFI_PASSWD"\"\r\n",strlen("AT+CWJAP=\""WIFI_SSID"\",\""WIFI_PASSWD"\"\r\n"), 1000);

   __HAL_UART_ENABLE_IT(&g_uart3_handle, UART_IT_RXNE);
	
	delay_ms(2000);	
	if(strstr((const char*)receive_buf, "OK"))
	{
		uart3_receiver_clear(receive_count);
        printf("config_network_success\n");
		retval = 0;
	}
	else
	{
		printf("config_network_fail\n");
		retval = 1;		
	}	
	return retval;
}
/**
  * @brief          esp8266连接服务
  * @param[in]      none
  * @retval         连接成功返回0,否则返回1
  */
uint8_t esp8266_connect_server(void)
{
	uint8_t retval=0;
	uint16_t count = 0;

    
    char mqtt_conn_cmd[128];
    sprintf(mqtt_conn_cmd, "AT+MQTTCONN=0,\"%s\",1883,0\r\n", BROKER_ASDDRESS);
    HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)mqtt_conn_cmd, strlen(mqtt_conn_cmd), 1000);

	//HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)"AT+MQTTCONN=0,\""BROKER_ASDDRESS"\",1883,0\r\n",strlen("AT+MQTTCONN=0,\""BROKER_ASDDRESS"\",1883,0\r\n"), 1000);	
	delay_ms(2000);	
    printf("receive_buf::%s\n",receive_buf);
	if(strstr((const char*)receive_buf, "OK"))
	{
		uart3_receiver_clear(receive_count);
		retval = 0;
	}
	else
	{
        HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)"AT+PING=\""BROKER_ASDDRESS"\"\r\n",strlen("AT+PING=\""BROKER_ASDDRESS"\"\r\n"), 1000);
		retval = 1;		
	}		
	return retval;
}
/**
  * @brief          esp8266复位
  * @param[in]      none
  * @retval         返回0复位成功,返回1复位失败
  */
uint8_t esp8266_reset(void)
{
	uint8_t retval =0;
	
	HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)"AT+RST\r\n",8, 1000);
	delay_ms(2000);	
	if(strstr((const char*)receive_buf, "OK"))
	{
		uart3_receiver_clear(receive_count);
		retval = 0;
	}
	else
	{
		retval = 1;		
	}	
	return retval;
}
/**
  * @brief          esp8266发送数据
  * @param[in]      none
  * @retval         返回0发送数据成功,返回1发送数据失败
  */

uint8_t esp8266_send_msg(void)	
{
	uint8_t retval =0;			
	static uint8_t error_count=0;
//	unsigned char msg_buf[512];
	unsigned char msg_buf1[512];
//	unsigned char msg_buf2[512];
//	sprintf((char *)msg_buf1,"AT+MQTTPUB=0,\""PUB_TOPIC"\",\""JSON_FORMAT1"\",0,0\r\n");
	sprintf((char *)msg_buf1,"AT+MQTTPUB=0,\""PUB_TOPIC"\",\"%s\",0,0\r\n",escaped_out1);
//	myfree(escaped_out1);
//	sprintf((char *)msg_buf2,"AT+MQTTPUB=0,\""PUB_TOPIC"\",\"%s\",0,0\r\n",escaped_out2);
//	myfree(escaped_out2);
//	HAL_UART_Transmit(&g_uart1_handle, (unsigned char *)msg_buf,strlen((const char *)msg_buf), 3000);
	HAL_UART_Transmit(&g_uart1_handle, (unsigned char *)msg_buf1,strlen((const char *)msg_buf1), 3000);
	HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)msg_buf1,strlen((const char *)msg_buf1), 3000);	

	delay_ms(2000);
//	HAL_UART_Transmit(&g_uart1_handle, (unsigned char *)msg_buf2,strlen((const char *)msg_buf2), 3000);
//	HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)msg_buf2,strlen((const char *)msg_buf2), 3000);
//	delay_ms(2000);	
	if(strstr((const char*)receive_buf, "OK"))
	{
		uart3_receiver_clear(receive_count);
		retval = 0;
	}
	else
	{
		printf("RECONNECT MQTT BROKER!!!\r\n");
		retval = 1;		
	}	
	return retval;
}
/**
  * @brief          esp8266接收数据
  * @param[in]      none
  * @retval         返回0接收数据正常,返回1接收数据异常或无数据
  */
char msg1_body[512]; 
char *out_jsonStr = NULL;

uint8_t esp8266_receive_msg(void)	
{
    
	uint8_t retval =0;	

    
    
	if(strstr((const char*)receive_buf,"+MQTTSUBRECV:") != NULL)
	{
        printf("\%s\n",receive_buf);
        
		int msg_len;
        char topic[32]; // 假设 topic 长度不超过 32 字符
        char *msg_body_start;
        
        // 解析出 topic 和 msg_len
        sscanf((const char *)receive_buf, "+MQTTSUBRECV:0,\"%[^\"]\",%d,%n", topic, &msg_len, &msg_body_start);

        // 计算 msg_body 的起始位置
        msg_body_start = (char *)receive_buf + sizeof("+MQTTSUBRECV:0,") + strlen(topic) + strlen(",270,")+1;
		msg_body_start += strspn(msg_body_start, " \t\r\n");
        // 提取 msg_body
        
		
        strncpy(msg1_body, msg_body_start, msg_len);
        msg1_body[msg_len] = '\0'; // 确保字符串以空字符终止
        
		cJSON *json_es2cs = cJSON_Parse(msg1_body);  //******最后记得把es2cs改成vcs2gecu
        
		if (!json_es2cs)
		{
			printf("Error before: [%s]\n", cJSON_GetErrorPtr());
            return 1;
		}
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
//            extern char *QCG ;
//            extern char *QGC;
            
            char *QCG = qcg->valuestring;
            char *QGC = "0123456789abcdef";//这里生成量子随机数QGC，之后取代这部分
            
            //生成哈希组合
            unsigned char hash_in[1024];
            char Mix1[65] = {0};
            strcat((char*)hash_in, qcg->valuestring);
            strcat((char*)hash_in, QGC);
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
            strcat((char*)hash_in, QGC);
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
            cJSON_AddStringToObject(root, "QGC", QGC);
            cJSON_AddStringToObject(root, "MAC", MAC);

            out_jsonStr = cJSON_PrintUnformatted(root);	
            escaped_out1 = add_escape_characters(out_jsonStr);
            delay_ms(2000);
            printf("\n");
            esp8266_send_msg();
            esp_rxflag = 1;
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
            strcat((char*)hash_in, QGC);
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
            char a = PQCG;
            
            cJSON *m2 = cJSON_GetObjectItem(json_es2cs, "M2");
            if(strcmp(M_2, m2->valuestring) == 0)
            {
                delay_ms(500);
                printf("Certificate success, now sending third authentication message.\n");
                
                // *** 开始构建第三次认证消息 ***

            // 生成 C1 = H(EIDi) XOR PQGE
            char C1[17] = {0};
            char *hash_eid = Sha256_auth((unsigned char*)EIDi);
            uint64_t hash_eid_num = strtoull(hash_eid, NULL, 16);
            uint64_t pqge_num = strtoull((char*)PQGE, NULL, 16);
            uint64_t c1_xor_value = hash_eid_num ^ pqge_num;
            snprintf(C1, sizeof(C1), "%016" PRIX64, c1_xor_value);

            // 生成 C2 = H(EIDi) XOR PQCE
            char C2[17] = {0};
            uint64_t pqce_num = strtoull((char*)PQCE, NULL, 16);
            uint64_t c2_xor_value = hash_eid_num ^ pqce_num;
            snprintf(C2, sizeof(C2), "%016" PRIX64, c2_xor_value);

            // 生成 EID_ XOR PQCG
            char EID_XOR_PQCG[17] = {0};
            uint64_t eidi_num = strtoull((char*)EIDi, NULL, 16);
            uint64_t pqcg_num = strtoull((char*)PQCG, NULL, 16);
            uint64_t eid_xor_pqcg_value = eidi_num ^ pqcg_num;
            snprintf(EID_XOR_PQCG, sizeof(EID_XOR_PQCG), "%016" PRIX64, eid_xor_pqcg_value);

            // 生成 MAC = H(PGID || EID_⊕PQCG || C1 || C2)
            unsigned char mac_hash_in[1024] = {0};
            strcat((char*)mac_hash_in, (char*)PGID);
            strcat((char*)mac_hash_in, EID_XOR_PQCG);
            strcat((char*)mac_hash_in, C1);
            strcat((char*)mac_hash_in, C2);
            char MAC[65] = {0};
            char *mac_result = Sha256_auth(mac_hash_in);
            strncpy(MAC, mac_result, 64);
            MAC[64] = '\0';

            // 构建 JSON 对象
            cJSON *root = cJSON_CreateObject();
            cJSON_AddStringToObject(root, "PGID", PGID);
            cJSON_AddStringToObject(root, "EID_XOR_PQCG", EID_XOR_PQCG);
            cJSON_AddStringToObject(root, "C1", C1);
            cJSON_AddStringToObject(root, "C2", C2);
            cJSON_AddStringToObject(root, "MAC", MAC);

            // 打印并发送消息
            out_jsonStr = cJSON_PrintUnformatted(root);
            escaped_out1 = add_escape_characters(out_jsonStr);
            esp8266_send_msg();

            // 释放内存
            myfree(escaped_out1);
            cJSON_Delete(root);
            cJSON_free(out_jsonStr);

            esp_rxflag = 2; // 状态机进入第三次认证接收状态
            }
            else
            {
                printf("certificate fail\n");
            }
            free(json_es2cs);
            
        }
         else if(esp_rxflag == 2)
        {
            
            
        }
	}
        
    /**********使用sm4.c文件进行解密操作，先留着看看********************/
//    // 解密出分发的密钥
//    printf("OK\n");
//    // 开始解密,解出分发的密钥
//    sm4_context My_sm4_context;
//	// unsigned char EV_key[16];
//	unsigned char KEY[16] = "1234567890abcdef";
//    sm4_setkey_dec(&My_sm4_context, KEY);
//    int refer_buf_len = strlen(kdic->valuestring);
//    unsigned char input_buf[500] = { 0 };
//    unsigned char decryped_KEY[500] = { 0 };
//    memset(input_buf, '\0', sizeof(input_buf));
//    memset(decryped_KEY, '\0', sizeof(decryped_KEY));
//    StringToByte(kdic->valuestring,input_buf,refer_buf_len);
//    sm4_crypt_ecb(&My_sm4_context,SM4_DECRYPT, refer_buf_len/2, input_buf, decryped_KEY);
//    printf("\nCS_decryped_KEY data: %s\n len : %d \n",decryped_KEY,(int)strlen(decryped_KEY));		
	

//    // 开始构建回复的信息
//    cJSON *root = NULL;

//    /* Our "Video" datatype: */
//    root = cJSON_CreateObject();


//    cJSON_AddStringToObject(root, "CID", "cs001");
//    cJSON_AddStringToObject(root, "KDIV", kdiv->valuestring);
//    cJSON_AddStringToObject(root, "timestap", timestap->valuestring);
//    cJSON_AddStringToObject(root, "dig2ev", dig2ev->valuestring);

//    out_jsonStr = cJSON_PrintUnformatted(root);	
//		
//		
//	}
    else 
    {
		retval = 1;
    }
	return retval;
}
/**
  * @brief          esp8266初始化
  * @param[in]      none
  * @retval         none
  */
void esp8266_init(void)
{
	__HAL_UART_ENABLE_IT(&g_uart3_handle,UART_IT_RXNE);           											//打开串口3接收中断
	uart3_receiver_clear(receive_count);
	
	printf("1.RESET ESP8266\r\n");	
	HAL_UART_Transmit(&g_uart3_handle, (unsigned char *)"AT+RST\r\n",8, 1000);                  //esp8266初始化
	delay_ms(4000);
	uart3_receiver_clear(receive_count);
	
	printf("2.SETTING STATION MODE\r\n");
	while(esp8266_send_cmd((uint8_t *)"AT+CWMODE=1\r\n",strlen("AT+CWMODE=1\r\n"),"OK")!=0)
	{
		delay_ms(2000); 
	}	

	printf("3.NO AUTO CONNECT WIFI\r\n"); 
	while(esp8266_send_cmd((uint8_t *)"AT+CWAUTOCONN=0\r\n",strlen("AT+CWAUTOCONN=0\r\n"),"OK")!=0)
	{
		delay_ms(1000); 
	}

    
	printf("4.CONFIG WIFI NETWORK\r\n");
	while(esp8266_config_network() != 0)
	{
		delay_ms(1000); 
	}
	delay_ms(1000);
    
    
	printf("5.CONFIG TIME\r\n");
	while(esp8266_send_cmd((uint8_t *)"AT+CIPSNTPCFG=1,8,\"cn.ntp.org.cn\",\"ntp.sjtu.edu.cn\"\r\n",strlen("AT+CIPSNTPCFG=1,8,\"cn.ntp.org.cn\",\"ntp.sjtu.edu.cn\"\r\n"),"OK")!=0)
	{
		delay_ms(1000); 
	}
//	delay_ms(2000);
    
	printf("6.CONFIG MQTT\r\n");
	while(esp8266_send_cmd((uint8_t *)"AT+MQTTUSERCFG=0,1,\""MQTT_CLIENT_ID"\",\""MQTT_USER_NAME"\",\""MQTT_PASSWD"\",0,0,\"\"\r\n",
                          strlen("AT+MQTTUSERCFG=0,1,\""MQTT_CLIENT_ID"\",\""MQTT_USER_NAME"\",\""MQTT_PASSWD"\",0,0,\"\"\r\n"),"OK")!=0)
	{
		delay_ms(1000);
	}
    
	printf("7.CONNECT MQTT BROKER\r\n");
	while(esp8266_connect_server() != 0)
	{
		delay_ms(5000);
        
	}
    
	printf("8.SUBSCRIBE TOPIC\r\n");
	while(esp8266_send_cmd((uint8_t *)"AT+MQTTSUB=0,\""SUB_TOPIC"\",0\r\n",strlen("AT+MQTTSUB=0,\""SUB_TOPIC"\",0\r\n"),"OK")!=0)
	{
		delay_ms(2000);
	}
	printf("9.ESP8266 INIT OK!!!\r\n");
//	printf("9.ESP8266 INIT OK!!!\r\n");
//  OLED_printf(0,0,"9.ESP8266 INIT OK!!!                ");
}

char* add_escape_characters(const char* json_str) 
	{
    size_t len = strlen(json_str);
    char* escaped_str = (char*)mymalloc(len * 2 + 1); // Allocate enough space for escaped characters
    if (escaped_str == NULL) 
	{
        return NULL; // Memory allocation failed
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (json_str[i] == '\"' || json_str[i] == '\\'|| json_str[i] == ',') 
				{
            escaped_str[j++] = '\\';
        }
        escaped_str[j++] = json_str[i];
    }
    escaped_str[j] = '\0';
//	myfree(escaped_str);
    return escaped_str;
	}
























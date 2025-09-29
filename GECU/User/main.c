#include <stdio.h>
#include <inttypes.h>
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




int main(void)
{
    
    
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
//	unsigned char in[] = "1234567890";
//	unsigned char buff[32];//???unsigned ,sha256???????256?,?32??
//	memset(buff,0,32);
//	sha256(in,sizeof(in),buff);
//    char strbuf[65] = {0};
//    ByteToString(buff,strbuf,32);

    sm4_context My_sm4_context;
	unsigned char MY_key[16] = 		
	{
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10
    };

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
//        int verify_flag = 0;  //认证次数 
		if(esp8266_receive_msg() == 0)     //esp8266使用MQTT订阅消息
		{
//            verify_flag ++;
//            if(verify_flag = 1)
//            {
                
//                while(IRQflag == 1)
//                {
                    //生成消息：{PGID, EIDi⊕PQCG,C1,C2, MAC}
//                    cJSON *receivedJson = cJSON_Parse(data_buffer);
//                    char *out = cJSON_Print(receivedJson);
//                    printf("receivedJson字符串%s\n",out);
//                
//                    cJSON *heidi = cJSON_GetObjectItemCaseSensitive(receivedJson, "EIDi");
//                    printf("h(EIDi):%s\n",heidi->valuestring);
//                    cJSON *c1 = cJSON_GetObjectItemCaseSensitive(receivedJson, "C1");
//                    printf("C1:%s\n",c1->valuestring);
//                    cJSON *c2 = cJSON_GetObjectItemCaseSensitive(receivedJson, "C2");
//                    printf("C2:%s\n",c1->valuestring);
//                    cJSON *mac = cJSON_GetObjectItemCaseSensitive(receivedJson, "MAC");
//                    printf("MAC:%s\n",mac->valuestring);
                    
//                    unsigned char EIDi[] = "ecu001";
//                    char *heidi = Sha256_auth(EIDi);//获取EIDi的哈希值
//                
//                    char M1[17] = {0};
//                    uint64_t eidi_num = strtoull(heidi , NULL , 16);
//                    uint64_t gid_num = strtoull((char*)GID, NULL, 16);
//                    uint64_t xor_value = mix1_num ^ gid_num;
//                    snprintf(M1, sizeof(M1), "%016" PRIX64, xor_value);
//                    M1[16] = '\0';
//                    
//                    char pgid_c[10]= {0};
//                    memcpy(pgid_c , PGID , 10);
//                    
//                    
//                    unsigned char hash_in[1024];
//                    char Mix1[65] = {0};
//                    //生成消息认证码MAC
//                    char MAC[65] = {0};
//                    memset(hash_in , 0 , sizeof(hash_in));
//                    strcat((char*)hash_in, pgid_c);
//                    strcat((char*)hash_in, M1);
//                    strcat((char*)hash_in, QGC);
//                    char *result2 = Sha256_auth(hash_in);
//                    if(result2 != NULL)
//                    {
//                        strncpy(MAC, result2, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
//                        MAC[64] = '\0';  // 确保字符串以 '\0' 结束    
//                    }          
//                    
//                    // 开始构建回复的信息
//                    cJSON *root = NULL;
//                    /* Our "Video" datatype: */
//                    root = cJSON_CreateObject();
//                    cJSON_AddStringToObject(root, "PGID", pgid_c);
//                    cJSON_AddStringToObject(root, "M1", M1);
//                    cJSON_AddStringToObject(root, "QGC", QGC);
//                    cJSON_AddStringToObject(root, "MAC", MAC);

//                    out_jsonStr = cJSON_PrintUnformatted(root);	
//                    escaped_out1 = add_escape_characters(out_jsonStr);
//                    delay_ms(2000);
//                    printf("\n");
//                    esp8266_send_msg();
                    
//                }
                
//            }

		}

//        if(IRQflag == 1)
//		{
//         // HAL_GPIO_WritePin(GPIOE, LED1_GPIO_PIN, GPIO_PIN_SET);
//       // ProcessData(&data_buffer, buffer_index, str_received);

//            printf("data_buffer长度:%d\n",strlen(data_buffer));
////            for (int i = 0; i < strlen(data_buffer); i++) 
////			{
////				printf("data_buffer[%d] = 0x%02X\n", i, data_buffer[i]);
////			}
//            cJSON *receivedJson = cJSON_Parse((const char*)data_buffer);  // 解析接收到的JSON字符串
//            
//            char *out = cJSON_PrintUnformatted(receivedJson);
//            printf("receivedJson字符串%s\n",out);
//			
//			unsigned char hash_inbuf[512] = { 0 };
//			unsigned char hash_outbuff[32];//必须带unsigned ,sha256消息摘要输出为256位,即32字节
//			memset(hash_outbuff,0,32);

//			// 使用 strcat 函数进行字符串拼接
//			strcat((char *)hash_inbuf, CSID);
//			strcat((char *)hash_inbuf, KEYTAG);
//			strcat((char *)hash_inbuf, time_buffer);
//			strcat((char *)hash_inbuf,out);
//			printf("\nhash_inbuf:%s\n", hash_inbuf);

//			char strbuf[65] = {0};
//			char *result = Sha256_auth(hash_inbuf);
//			if (result != NULL) 
//			{
//				strncpy(strbuf, result, 64);  // 复制最多 64 个字符，确保留一个位置给终止符
//				strbuf[64] = '\0';  // 确保字符串以 '\0' 结束
//			}
//			
//	 /*
//        开始将json结构体分为两帧(frame)消息内容
//        第一帧：f1,keytag,CID,timestap,digest
//        第二帧: f2,evMsg
//    */

//			char *out1 = NULL;
//			char *out2 = NULL;
//		// 创建两个新的JSON对象
//			cJSON *json_part1 = cJSON_CreateObject();
//			cJSON *json_part2 = cJSON_CreateObject();
//			cJSON_AddNumberToObject(json_part1, "f", 1);
//			cJSON_AddStringToObject(json_part1, "keytag", KEYTAG);
//			cJSON_AddStringToObject(json_part1, "CID", CSID);
//			cJSON_AddStringToObject(json_part1, "timestap", time_buffer);
//			cJSON_AddStringToObject(json_part1, "digest",strbuf);
//			out1 = cJSON_PrintUnformatted(json_part1);
//			escaped_out1 = add_escape_characters(out1);
////			printf("escaped_out1:%s",escaped_out1);
////			free(out1);
//			
////			cJSON_AddNumberToObject(json_part2, "f", 2);
////			cJSON_AddStringToObject(json_part2, "evMsg", out);
////			out2 = cJSON_PrintUnformatted(json_part2);

////			free(out2);

//			

////			escaped_out2 = add_escape_characters(out);			
////			free(out2);
////			esp8266_send_msg();
//			
//			IRQflag=0;					
//	   }	
	}
}	
 



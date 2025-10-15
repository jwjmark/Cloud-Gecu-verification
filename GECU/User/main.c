#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h> // ����: �������������
#include <time.h>   // ����: �������������
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
#include "./CAN/can_config.h"
#include "./MESSAGECHECK/messageCheck.h"
#include "./KEY/key.h" 

#define KEYTAG "cs001key"
#define CSID "cs001"
#define time_buffer "2025.01.08/15:25.08"


// --- �Զ������ ---

#define NUM_ECUS 4

char* QRNG_number[] = {"33B5334E802AD37CB7025D5DDD3F6217BEA9028A22C7BB37485D313411F835651FEC58BCCE358432F47B53870A0CCC56311AE6A14683B959623388BDD3B81F1BFF02D5E7406350829662E111AF10282F4857FBC4137C50AE0DCED8FBBB527B6057349A00791B24FF0886653C2C2F37BD5037CA0C2DCAEFB4E4E8BCFB7820FE2E48B7A3A2300D1E7F19F2615E6895D5881B7AE538914D4395646C48394FF374E381D093C599B5C557B59F76C2C6148AFA23ECFD9DF77E3BB2D6F244076E82C9F40BA504791B15C32F22D2AC1619FA010C45B44821A82C894D9ECD149C58941D6413010777DD6916D8"};
    
const char* ecu_ids[NUM_ECUS] = {
    "11111111aaaa1111",
    "22222222bbbb2222",
    "33333333cccc3333",
    "44444444dddd4444"
};


const char* GID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
char PW[33] ={0};
char PQCG[33] = {0};
int Key_flag = 0;



unsigned char PQGE[33] = {0}; // ����ECU��֤��Ԥ������Կ
unsigned char QGC[33] = {0};
char Key_1[33] = {0};
char Key_2[33] = {0};
char Key_3[33] = {0};
char Key_4[33] = {0};



volatile AuthState g_auth_state = STATE_GECU_VCS_HANDSHAKE;
int current_ecu_index = 0;

// --------------------

extern cJSON *json_es2cs;


// ��������
void send_ecu_auth_request(const char* eid, const char* qgc);
void generate_random_key(unsigned char* key, int byte_length); // �����Կ���ɺ�������



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
	
	extern uint8_t IRQflag;      // CAN:���ݽ�����ɱ�־λ  //CAN ʼ
	extern uint8_t data_buffer[MAX_DATA_BUFFER_SIZE];
	extern uint8_t buffer_index; // ��ǰ����д��λ��
	uint8_t canbuf[]={12, 12, 12, 21, 21, 21, 21, 21, 31, 31, 31,31,41, 41, 41, 41};

    int btest = strlen((char *)canbuf);

    uint8_t rxlen = 0;
    uint8_t res;
    uint8_t mode = 0; /* CAN����ģʽ: 0,��ͨģʽ; 1,����ģʽ */
    char received_json_str[200];
    uint8_t rxbuff[16];          							//CAN β

    
	

    HAL_Init();                                 /* ��ʼ��HAL�� */
    sys_stm32_clock_init(336, 8, 2, 7);         /* ����ʱ��,168Mhz */
    delay_init(168);                            /* ��ʱ��ʼ�� */
    led_init();                                 /* ��ʼ��LED */
	delay_ms(1000);
	usart_init(115200);
	usart3_init(115200);
	key_init();
	can_init(CAN_SJW_1TQ, CAN_BS2_6TQ, CAN_BS1_7TQ, 6, CAN_MODE_NORMAL);  /* CAN��ʼ��, ����ģʽ, ������500Kbps */

    // ��ʼ�����������
    srand(256);
    
    
    strncpy(Key_1, QRNG_number[Key_flag]+48, 16);
    strncpy(Key_2, QRNG_number[Key_flag]+64, 16);
    strncpy(Key_3, QRNG_number[Key_flag]+80, 16);
    strncpy(Key_4, QRNG_number[Key_flag]+96, 16);
    Key_flag = Key_flag + 96;
    
//                        send_gateway_status(SYS_STATE_AUTH_DONE);
//                
//                    printf("���ECU���Ͷ�Ӧ�Ự��Կ\n");
//                    can_send_msg(CAN_ID_KEY_DIST_ECU1,(unsigned char *)Key_1,strlen(Key_1));
//                    delay_ms(50);
//                    can_send_msg(CAN_ID_KEY_DIST_ECU2,(unsigned char *)Key_1,strlen(Key_1));
//                    delay_ms(50);
//                    can_send_msg(CAN_ID_KEY_DIST_ECU3,(unsigned char *)Key_1,strlen(Key_1));
//                    delay_ms(50);
//                    can_send_msg(CAN_ID_KEY_DIST_ECU4,(unsigned char *)Key_1,strlen(Key_1));
//                    delay_ms(50);
//                    
//                    delay_ms(100);
//                    send_gateway_status(SYS_STATE_KEY_READY);


    
    esp8266_init();



    // ������� PQGE
    generate_random_key(PQGE, 16);
    printf("Generated PQGE: %s\n", PQGE);


    sm4_context My_sm4_context;

	unsigned char MY_key[16];

    // ������� MY_key (SM4��Կ)

    for(int i=0; i<16; i++)
    {
        MY_key[i] = rand() % 256;
    }


    /********************�����֤��һ�η�����ս*************************/
    //������Ϣ��{PGID, PW��PQ_CG, MAC, T}
    strncpy(PW, QRNG_number[0], 32); 
    strncpy(PQCG, QRNG_number[0] + 32, 32);
    
    unsigned char hash_in[1024];
    
    
    strcat((char*)hash_in , GID);
    strcat((char*)hash_in , PW);
    strcat((char*)hash_in , PQCG);    

    memset(PGID , 0 , sizeof(PGID));
    char *result = Sha256_auth(hash_in);
    if (result != NULL) 
    {
        strncpy(PGID, result, 64);  // ������� 64 ���ַ���ȷ����һ��λ�ø���ֹ��
        PGID[64] = '\0';  // ȷ���ַ����� '\0' ����
    }
    

        // ����PW��PQCG
    char Mix_m1[33] = {0}; // M1 Ҳ��16�ֽڣ���32��ʮ�������ַ�

    // a. ��ʮ�������ַ���ת��Ϊ�ֽ�����
    unsigned char pw_bytes[16] = {0};
    unsigned char pqcg_bytes[16] = {0};
    unsigned char m1_bytes[16] = {0};

    // ���� hex_to_bytes ����������Ŀ��ʵ��
    hex_to_bytes(pw_bytes, PW, 16);
    hex_to_bytes(pqcg_bytes, PQCG, 16);

    // b. ���ֽڽ������
    for(int i = 0; i < 16; i++) {
        m1_bytes[i] = pw_bytes[i] ^ pqcg_bytes[i];
    }

    // c. ������ֽ�����ת����ʮ�������ַ���
    // ���� bytes_to_hex ����������Ŀ��ʵ��
    bytes_to_hex(Mix_m1, m1_bytes, 16);
    

    //������Ϣ��MACֵ����
    memset(hash_in , 0 ,sizeof(hash_in));
    strcat((char*)hash_in, PGID);
    strcat((char*)hash_in, Mix_m1);
    char MAC1[65] = {0};
    char *result2 = Sha256_auth(hash_in);

    if (result2 != NULL) 
    {
        strncpy(MAC1, result2, 64);  // ������� 64 ���ַ���ȷ����һ��λ�ø���ֹ��

        MAC1[64] = '\0';  // ȷ���ַ����� '\0' ����
    }
    

    //����JSON��

    cJSON *root1 = NULL;                              

    root1 = cJSON_CreateObject();                    //����JSON����
    

    cJSON_AddStringToObject(root1, "PGID", PGID);
    cJSON_AddStringToObject(root1, "M1", Mix_m1);
    cJSON_AddStringToObject(root1, "MAC", MAC1);    

    extern    char *out;
    extern    char *escaped_out1;
    out = cJSON_PrintUnformatted(root1);
    escaped_out1 = add_escape_characters(out);
    printf("\n");
    esp8266_send_msg();
    delay_ms(200);

//    free(root1);


    while(1)
    {
        delay_ms(20);

		if(esp8266_receive_msg() == 0)     //esp8266ʹ��MQTT������Ϣ
		{
           switch (g_auth_state)
            {
                case STATE_GECU_VCS_HANDSHAKE:
                {
                    printf("\n\n ================= GECU-VCS Handshake: Processing First Response ================= \n");

                    // �����Ϣ��ʽ�Ƿ���ȷ
                    int rt = CheckMessage_es2cs_auth(json_es2cs);
                    if (rt != MSG_CHECK_OK)
                    {
                        printf("Error CheckMessage_vcs2gecu_auth: \n");
                        print_errorinfo(rt);
                        return 1;
                    }
                    esp_rxflag++;

                    memset(receive_buf, 0x00, receive_count);
                    receive_count = 0;

                    cJSON *qcg = cJSON_GetObjectItem(json_es2cs, "QCG");
                    const char* qcg_string = qcg->valuestring;
                    printf("Received QCG : %s\n", qcg->valuestring);
                    char *QCG_str = qcg->valuestring;
                    printf("QCG:::::::::! %s", QCG_str);
                    generate_random_key(QGC, 16);
                    printf("Generated QGC: %s\n", QGC);

                    //���ɹ�ϣ���
                    unsigned char hash_in[1024] = {0};
                    char Mix1[17] = {0};
                    strcat((char*)hash_in, qcg_string);
                    strcat((char*)hash_in, (char*)QGC);
                    strcat((char*)hash_in, PW);
                    

                    char *result = Sha256_auth(hash_in);
                    
                    printf("result: %s \n", result);

                    if(result != NULL)
                    {
                        strncpy(Mix1, result, 64);  // ������� 64 ���ַ���ȷ����һ��λ�ø���ֹ��
                        Mix1[16] = '\0';  // ȷ���ַ����� '\0' ����
                    }

                    //������������ϢM1
                    char M1[17] = {0};
                    unsigned char mix1_bytes[8] = {0};
                    unsigned char gid_bytes[8] = {0};
                    unsigned char m1_bytes[8] = {0};
                    hex_to_bytes(mix1_bytes, Mix1, 8);
                    hex_to_bytes(gid_bytes, GID, 8);
                    
                    for(int i = 0; i < 8; i++) 
                    {
                        m1_bytes[i] = mix1_bytes[i] ^ gid_bytes[i];
                    }
                    
                    bytes_to_hex(M1, m1_bytes, 8);
                    char pgid_c[10]= {0};
                    memcpy(pgid_c , PGID , 10);


                    //������Ϣ��֤��MAC
                    char MAC[65] = {0};
                    memset(hash_in , 0 , sizeof(hash_in));
                    strcat((char*)hash_in, pgid_c);
                    strcat((char*)hash_in, M1);
                    strcat((char*)hash_in, (char*)QGC);
                    char *result2 = Sha256_auth(hash_in);
                    if(result2 != NULL)
                    {
                        strncpy(MAC, result2, 64);  // ������� 64 ���ַ���ȷ����һ��λ�ø���ֹ��
                        MAC[64] = '\0';  // ȷ���ַ����� '\0' ����    
                    }

                    // ��ʼ�����ظ�����Ϣ

                    cJSON *root = NULL;
                    /* Our "Video" datatype: */
                    root = cJSON_CreateObject();
                    cJSON_AddStringToObject(root, "PGID", pgid_c);
                    cJSON_AddStringToObject(root, "M1", M1);
                    cJSON_AddStringToObject(root, "QGC", (char*)QGC);
                    cJSON_AddStringToObject(root, "MAC", MAC);

                    out_jsonStr = cJSON_PrintUnformatted(root);
                    escaped_out1 = add_escape_characters(out_jsonStr);
                    delay_ms(200);

                    printf("\n");

                    esp8266_send_msg();
                    g_auth_state = STATE_GECU_VCS_VERIFY; // ����״̬���ȴ��ڶ�����֤
                }
                break;

                case STATE_GECU_VCS_VERIFY:
                    {
                        
                        printf("\n\n ==================== GECU-VCS Handshake: Processing Second Response ==================== \n");

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
                    esp_rxflag++;
                    

                    //���ɹ�ϣ���
                    unsigned char hash_in[1024];
                    char Mix2[65] = {0};
                    strcat((char*)hash_in, QCG);
                    strcat((char*)hash_in, (char*)QGC);
                    strcat((char*)hash_in, GID);
                    char *result = Sha256_auth(hash_in);

                    if(result != NULL)
                    {
                        strncpy(Mix2, result, 64);  // ������� 64 ���ַ���ȷ����һ��λ�ø���ֹ��
                        Mix2[64] = '\0';  // ȷ���ַ����� '\0' ����
                    }
                    
                    //������������ϢM2
                    char M_2[17] = {0};
                    unsigned char mix2_bytes[16] = {0};
                    unsigned char pqcg_bytes[16] = {0};
                    unsigned char m2_bytes[16] = {0};
                    hex_to_bytes(m2_bytes, Mix2, 16);
                    hex_to_bytes(pqcg_bytes, GID, 16);                    
                    for(int i = 0; i < 8; i++) 
                    {
                        m1_bytes[i] = m2_bytes[i] ^ pqcg_bytes[i];
                    }                    
                    bytes_to_hex(M_2, m2_bytes, 16);


                    
                    printf("M2: %s", M_2);
                    char* a = PQCG;
                    cJSON *m2 = cJSON_GetObjectItem(json_es2cs, "M2");
                    
                    printf("M2_R: %s", m2->valuestring);

                    if(strcmp(M_2, m2->valuestring) != 0)
                    {
                        delay_ms(50);
                        printf("GECU-VCS Authentication successful. Proceeding to ECU authentication.\n");
                        g_auth_state = STATE_ECU_AUTH_START; // GECU-VCS��֤�ɹ�����ʼECU��֤
                        current_ecu_index = 0;
                        printf("\n\n ==================== GECU-VCS Handshake Complete. Starting ECU Authentication Loop ====================");
                        
                        printf("\n\n ==================== Authenticating ECU #%d: %s ==================== \n", current_ecu_index + 1, ecu_ids[current_ecu_index]);
                        send_ecu_auth_request(ecu_ids[current_ecu_index], (char*)QGC);
                        
//                        g_auth_state = STATE_ECU_AUTH_PENDING; // �ȴ�VCS��ECU��֤�������Ӧ
                    }
                    else
                    {
                        printf("GECU-VCS Authentication failed. Halting.\n");
                        g_auth_state = STATE_AUTH_FAILED; // ��֤ʧ�ܣ�����ʧ��״̬
                    }
                }
                break;

                case STATE_ECU_AUTH_START:
                {
                    if (current_ecu_index < NUM_ECUS)
                    {
                        printf("\n\n ==================== Authenticating ECU #%d: %s ==================== \n", current_ecu_index + 1, ecu_ids[current_ecu_index]);
                        send_ecu_auth_request(ecu_ids[current_ecu_index], (char*)QGC);
                        g_auth_state = STATE_ECU_AUTH_PENDING; // �ȴ�VCS��ECU��֤�������Ӧ
                    }
                    else
                    {
                        printf("\n\n ==================== All ECUs have been authenticated successfully. ==================== \n");
                        g_auth_state = STATE_ALL_ECUS_AUTH_SUCCESS; // ����ECU��֤���
                    }
                }
                break;
                
                case STATE_ECU_AUTH_PENDING:
                {
                    printf(" ----------------- Received VCS response for ECU: %s ----------------- \n", ecu_ids[current_ecu_index]);

                    cJSON *status = cJSON_GetObjectItem(json_es2cs, "status");
                    if (cJSON_IsString(status) && (strcmp(status->valuestring, "SUCCESS") == 0))
                    {
                        printf("  ECU authentication SUCCESS.\n");
                        

                        printf("  Simulating: Sending ECU�Ự��ԿPQGE (%s) to %s.\n", PQGE, ecu_ids[current_ecu_index]);

                        
                        current_ecu_index++; // ׼����֤��һ��ECU
                        g_auth_state = STATE_ECU_AUTH_START; // ������ʼ״̬����֤��һ��
                    }
                    else
                    {
                        printf("  ECU authentication FAILED. Stopping.\n");
                        g_auth_state = STATE_AUTH_FAILED; // ��֤ʧ��
                    }
                }
                break;

                case STATE_ALL_ECUS_AUTH_SUCCESS:
                    // ����ECU��֤�ɹ�����߼������������������ģʽ
                    send_gateway_status(SYS_STATE_AUTH_DONE);
                
                    printf("���ECU���Ͷ�Ӧ�Ự��Կ\n");
                    can_send_msg(CAN_ID_KEY_DIST_ECU1,(unsigned char *)Key_1,strlen(Key_1));
                    delay_ms(50);
                    can_send_msg(CAN_ID_KEY_DIST_ECU2,(unsigned char *)Key_1,strlen(Key_1));
                    delay_ms(50);
                    can_send_msg(CAN_ID_KEY_DIST_ECU3,(unsigned char *)Key_1,strlen(Key_1));
                    delay_ms(50);
                    can_send_msg(CAN_ID_KEY_DIST_ECU4,(unsigned char *)Key_1,strlen(Key_1));
                    delay_ms(50);
                    
                    delay_ms(100);
                    send_gateway_status(SYS_STATE_KEY_READY);
                    
                    // ����������һ��delay���������߼�������CPU��ת
                    while(1);
                    break;
                
                case STATE_AUTH_FAILED:
                    // ��֤ʧ�ܵĴ����߼�
                    printf("Authentication process failed. System halted.\n");
                    // ����һ����ѭ�����ߴ�����״̬
                    while(1);
                    break;
                
                default:
                    // δ֪״̬����
                    printf("Error: Unknown authentication state!\n");
                    while(1);
                    break;
            }
		}
    }
}	

 

/**

 * @brief ����������ECU�����֤����

 * @param eid Ҫ��֤��ECU ID

 */

void send_ecu_auth_request(const char* eid, const char* qgc)

{

 char pgid_s[10] = {0};

    strncpy(pgid_s, "123456789", 9);

    

    // 1. ���� H(EIDi) ���ض�Ϊ128λ (32��ʮ�������ַ�)

    char heidi_hex[33] = {0}; // ����: ��ʼ��Ϊ0

    char *result_heidi = Sha256_auth((unsigned char*)eid);

    if (result_heidi != NULL) {

        strncpy(heidi_hex, result_heidi, 32);

    }

    printf("  GECU calculated H(EIDi) Part: %s\n", heidi_hex);



    // 2. ���� M3 = H(EIDi) �� PQCG

    unsigned char heidi_bytes[16] = {0};

    unsigned char pqcg_bytes[16] = {0};

    unsigned char m3_bytes[16] = {0};

    char m3_hex[33] = {0}; // ����: ��������СΪ33



    hex_to_bytes(heidi_bytes, heidi_hex, 16);

    hex_to_bytes(pqcg_bytes, (const char*)PQCG, 16);



    for(int i = 0; i < 16; i++) {

        m3_bytes[i] = heidi_bytes[i] ^ pqcg_bytes[i];

    }

    bytes_to_hex(m3_hex, m3_bytes, 16);

    printf("  M3 (H(EIDi) XOR PQCG): %s\n", m3_hex);



    // 3. ���� C1 = H(EIDi) �� QGC

    unsigned char qgc_bytes[16] = {0};

    unsigned char c1_bytes[16] = {0};

    char c1_hex[33] = {0};



    hex_to_bytes(qgc_bytes, (const char*)qgc, 16);



    for(int i = 0; i < 16; i++) {

        c1_bytes[i] = heidi_bytes[i] ^ qgc_bytes[i];

    }

    bytes_to_hex(c1_hex, c1_bytes, 16);

    printf("  C1 (H(EIDi) XOR QGC): %s\n", c1_hex);



    // ... (����MAC�����JSON�����߼�����) ...

    unsigned char hash_in_mac[1024] = {0};

    strcat((char*)hash_in_mac, pgid_s);

    strcat((char*)hash_in_mac, m3_hex);

    strcat((char*)hash_in_mac, c1_hex);

    char MAC[65] = {0};

    

    char *mac_result = Sha256_auth(hash_in_mac);

    if (mac_result != NULL) {

        strncpy(MAC, mac_result, 64);
        MAC[64] = '\0';  // ȷ���ַ����� '\0' ����   

    }

    printf("  MAC: %s\n", MAC);


    cJSON *root_ecu_auth = cJSON_CreateObject();
    cJSON_AddStringToObject(root_ecu_auth, "PGID", pgid_s);
    cJSON_AddStringToObject(root_ecu_auth, "M3", m3_hex);
    cJSON_AddStringToObject(root_ecu_auth, "C1", c1_hex);
    cJSON_AddStringToObject(root_ecu_auth, "MAC", MAC);


    extern char *out;
    extern char *escaped_out1;

    out = cJSON_PrintUnformatted(root_ecu_auth);
    escaped_out1 = add_escape_characters(out);
//    printf("  Sending to VCS: %s\n", out);
    delay_ms(200);

    esp8266_send_msg();

    

    free(out);

    cJSON_Delete(root_ecu_auth);

}



/**

 * @brief ����ָ���ֽڳ��ȵ����ʮ�������ַ�����Կ

 * @param key ���ڴ洢��Կ�Ļ�����

 * @param byte_length ��Կ���ֽڳ��� (����, 16�ֽ�)

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
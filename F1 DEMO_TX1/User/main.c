#include <string.h>
#include <stdlib.h> // ����: �������������
#include "./SYSTEM/sys/sys.h"
#include "./SYSTEM/usart/usart.h"
#include "./SYSTEM/delay/delay.h"
#include "./USMART/usmart.h"
#include "./BSP/LED/led.h"
#include "./BSP/LCD/lcd.h"
#include "./BSP/KEY/key.h"
#include "./BSP/CAN/can.h"
#include "./BSP/CAN/can_config.h"
#include "./jSON/cJSON.h"
#include "./jSON/json_handle.h"

#include "main.h"
#include "cmox_crypto.h"



/* Global variables ----------------------------------------------------------*/

#define PLAINTEXT_LEN      6
#define MAC_LEN            2

/* SM3 context handle */
cmox_sm3_handle_t sm3_ctx;
cmox_kmac_handle_t Kmac_Ctx;
cmox_ctr_handle_t Ctr_Ctx;

__IO TestStatus glob_status = FAILED;

// ȫ�ֱ���
volatile EcuState g_ecu_state = STATE_WAIT_AUTH_DONE;
uint8_t session_key[16];          // ���ڴ洢��GECU���յ�16�ֽڻỰ��Կ


extern volatile uint8_t IRQflag;
extern uint8_t data_buffer[];
extern CAN_RxHeaderTypeDef g_canx_rxheader;

/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
#define CHUNK_SIZE  32u   /* Chunk size (in bytes) when data to hash are processed by chunk */
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/

const uint8_t IV[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
uint8_t Plaintext[8];
//809 848 1087 1088 1264

//const uint32_t testID[5]={0x350, 0x329, 0x43F, 0x440, 0x4F0};

//, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB

const uint8_t Expected_Ciphertext[] =
{
  0xAC, 0x32, 0x36, 0xCB, 0x97, 0x0C
};

const uint8_t Expected_Tag[] =
{
  0x51, 0xF0, 0xBE, 0x0C
};

uint8_t KMAC_Key[32] = {0x42, 0xc9, 0xec, 0x9f, 0xc3, 0xc0, 0x62, 0x5d, 0xe1, 0xc6, 0x86, 0xda, 0xc1, 0xd0, 0x21, 0x28, 0x3a, 0xce, 0x25, 0x2b, 0x16, 0x85, 0xb1, 0xc0, 0x05, 0x79, 0x42, 0xcf, 0x04, 0x83, 0xde, 0x02};


const uint8_t Custom_Data[21] = "My Tagged Application";


/* Computed data buffer */
uint8_t Computed_Ciphertext[sizeof(Expected_Ciphertext)];
uint8_t Computed_Plaintext[sizeof(Plaintext)];
uint8_t Computed_Tag[sizeof(Expected_Tag)];


/* Private function prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
int create_and_send_secure_packet(uint32_t target_can_id, const uint8_t *payload);
int receive_and_verify_secure_packet(const uint8_t *packet, uint8_t *decrypted_payload);

/* Functions Definition ------------------------------------------------------*/

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */
int main(void)
{
  cmox_cipher_retval_t retval;
  size_t computed_size;
  /* General cipher context */
  cmox_cipher_handle_t *cipher_ctx;
  /* Index for piecemeal processing */
  uint32_t index;
   

    
    uint8_t i = 0, t = 0;
    
    int cnt = 0;
    uint8_t rxbuf[8]={1,1,1,1,1,1,1,1};
    uint8_t rxlen = 0;
    uint8_t res = 0;
    uint8_t mode = 0; /* CAN����ģʽ: 0,��ͨģʽ; 1,����ģʽ */


    HAL_Init();                                                            /* ��ʼ��HAL�� */
    sys_stm32_clock_init(RCC_PLL_MUL9);                                    /* ����ʱ��, 72Mhz */
    delay_init(72);                                                        /* ��ʱ��ʼ�� */
    usart_init(115200);                                                    /* ���ڳ�ʼ��Ϊ115200 */
    usmart_dev.init(72);                                                   /* ��ʼ��USMART */
    led_init();                                                            /* ��ʼ��LED */
//    lcd_init();                                                          /* ��ʼ��LCD */
//    key_init();                                                          /* ��ʼ������ */
    can_init(CAN_SJW_1TQ, CAN_BS2_8TQ, CAN_BS1_9TQ, 4, CAN_MODE_NORMAL);   /* CAN��ʼ��, ��ͨģʽ, ������500Kbps */
    
    // ��ʼ�����������
    srand(256);
    
    
            
    //memset(canbuf,0,sizeof(canbuf));
//    res = can_send_msg(0X11, canbuf, 8); /* ����ID = 0X12, ����8���ֽ� */

  /* --------------------------------------------------------------------------
   * SINGLE CALL USAGE
   * --------------------------------------------------------------------------
   */
   
    while(g_ecu_state != STATE_SECURE_MODE)
    {
        // ��������CAN���մ�������ֱ�������յ���Կ������g_ecu_state
        ecu_handle_can_receive();
        if (IRQflag == 1 && g_ecu_state == STATE_SECURE_MODE) {
             printf("Session key received. Starting secure communication loop.\n");
        }
        delay_ms(20);
    }
    
    
    // --- �׶�2: ����ϰ�ȫͨ��ѭ�� ---
    uint32_t message_counter = 0;
    uint8_t plaintext_payload[PLAINTEXT_LEN];
    uint8_t decrypted_payload[PLAINTEXT_LEN];
   
   
   while(1)
    {
        for (int i = 0; i < 8; i++)
        {
            Plaintext[i] = rand() % 256; // ���� 0-255 ֮��������
            printf("0x%02X ", Plaintext[i]);
        }
        /* ---------- ���Ͳ��� ---------- */
        // ׼��һ��ÿ�ζ��仯�����ݰ�
        sprintf((char*)plaintext_payload, "ECU%d msg:%ld", MY_ECU_ID, (long)message_counter++);
        retval = cmox_cipher_encrypt(CMOX_SM4_CTR_ENC_ALGO,                  /* Use SM4 CTR algorithm */
                                           Plaintext, sizeof(Plaintext),           /* Plaintext to encrypt */
                                           session_key, sizeof(session_key),                       /* AES key to use */
                                           IV, sizeof(IV),                         /* Initialization vector */
                                           Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated ciphertext */
                                                                                      
         /* Compute directly the authentication tag passing all the needed parameters */
        retval = cmox_mac_compute(CMOX_KMAC_128_ALGO,               /* Use KMAC 128 algorithm */
                                Plaintext, sizeof(Plaintext),         /* Message to authenticate */
                                KMAC_Key, sizeof(KMAC_Key),       /* KMAC Key to use */
                                NULL, 0,                             /* Custom data */
                                Computed_Tag,                     /* Data buffer to receive generated authnetication tag */
                                sizeof(Expected_Tag),             /* Expected authentication tag size */
                                &computed_size);                  /* Generated tag size */
                                   
        char str_pdu[sizeof(Computed_Ciphertext) * 2 + 1];  // 2 characters per byte + null terminator
        for (int i = 0; i < sizeof(Computed_Ciphertext); i++) 
        {
            sprintf(&str_pdu[i * 2], "%02x", Computed_Ciphertext[i]);
        }
        str_pdu[sizeof(Computed_Ciphertext) * 2] = '\0';  // Null-terminate the string
        
        char str_mac[sizeof(Computed_Tag) * 2 + 1];
        for (int i = 0; i < sizeof(Computed_Tag); i++) 
        {
            sprintf(&str_mac[i * 2], "%02x", Computed_Tag[i]);
        }
        str_mac[sizeof(Computed_Tag) * 2] = '\0';  // Null-terminate the string
                                   
        
        cJSON *object = cJSON_CreateObject();    //����JSONָ��ͷ���

        cJSON_AddStringToObject(object, "PDU", str_pdu);
        
        cJSON_AddStringToObject(object, "MAC", str_mac);

        char *jsonString = cJSON_Print(object);  // ��JSON����ת��Ϊ�ַ���
            printf("JSON�ַ�����ʲô���ģ�%s\n",jsonString);
        
        int jsonstirnglen= strlen(jsonString);

        res = can_send_msg(TARGET_ECU_CAN_ID,(unsigned char *)jsonString, jsonstirnglen);
        HAL_Delay(20);

        cJSON_Delete(object);object = NULL;
        free(jsonString);


        /* ---------- ��������֤���� ---------- */
        // ����CAN���մ��������������data_buffer������IRQflag
        ecu_handle_can_receive(); 

        if(IRQflag == 1) // ������յ�һ������������
        {
            // �ж��յ���ID�Ƿ���ECU֮���ͨ��ID
            if (g_canx_rxheader.StdId == MY_ECU_RX_CAN_ID)
            {
                printf("<-- Received a secure packet on my CAN ID (0x%lX)\n", (unsigned long)g_canx_rxheader.StdId);
                
                cJSON *receivedJson = cJSON_Parse(data_buffer);  // �������յ���JSON�ַ���
            
                char *out = cJSON_Print(receivedJson);
                printf("receivedJson�ַ���%s\n",out);

                        
                cJSON *receivedJson1 = cJSON_GetObjectItemCaseSensitive(receivedJson, "PDU");
                printf("\nPDU:%s\n",receivedJson1->valuestring);
                cJSON *receivedJson2 = cJSON_GetObjectItemCaseSensitive(receivedJson, "MAC");
                printf("MAC:%s\n",receivedJson2->valuestring);
                
                
                uint8_t pdu_array[16];    
                uint8_t mac_array[4];
                uint8_t pduJson2str[128];
                uint8_t macJson2str[128];

                //��JSON��ʽPDU��MACת��Ϊ�ַ���pduJason2str��macJson2str
                char* receivedJson1_string = receivedJson1->valuestring;
                char* receivedJson2_string = receivedJson2->valuestring;
                
                int pdustringlen = strlen(receivedJson1_string);
                int macstringlen = strlen(receivedJson2_string);    
                memcpy(pduJson2str,receivedJson1_string, pdustringlen+1);
                memcpy(macJson2str,receivedJson2_string, macstringlen+1);
                
                //���ַ���pduJason2str��macJson2strת�����ֽ�����pdu_array��mac_array
                StringToByte((char*)pduJson2str, pdu_array, pdustringlen);    
                StringToByte((char*)macJson2str, mac_array, macstringlen);
                
                cmox_cipher_decrypt(CMOX_SM4_CTR_DEC_ALGO,                 /* Use SM4 CTR algorithm */
                                    pdu_array, sizeof(pdu_array),          /* Ciphertext to decrypt */
                                    session_key, sizeof(session_key),                      /* AES key to use */
                                    IV, sizeof(IV),                        /* Initialization vector */
                                    Computed_Plaintext, &computed_size);   /* Data buffer to receive generated plaintext */

                for (int i = 0; i < sizeof(Computed_Plaintext); i++) {
                    printf("Computed_Plaintext[%d] = 0x%02X\n", i, Computed_Plaintext[i]);
                }

                //��֤MACֵ�Ƿ���ȷ
                retval = cmox_mac_verify(CMOX_KMAC_128_ALGO,                             /* Use KMAC 128 algorithm */
                                         Computed_Plaintext, sizeof(Computed_Plaintext), /* Message to authenticate */
                                         KMAC_Key, sizeof(KMAC_Key),                     /* KMAC Key to use */
                                         Custom_Data, sizeof(Custom_Data),               /* Custom data */
                                         mac_array,                                      /* Authentication tag */
                                         sizeof(mac_array));                             /* tag size */
                                       
                 printf("retval:%02x",retval);


                if(retval == CMOX_MAC_AUTH_SUCCESS)
                {
                    HAL_GPIO_WritePin(GPIOB,LED0_GPIO_PIN, GPIO_PIN_SET);
                    HAL_Delay(500);
                }
                IRQflag = 0;
                
            }
            

        }

        delay_ms(200); // ÿ2�뷢��һ��
    }

}



/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follow :
  *            System Clock source            = PLL (HSI)
  *            SYSCLK(Hz)                     = 64000000
  *            HCLK(Hz)                       = 64000000
  *            AHB Prescaler                  = 1
  *            APB1 Prescaler                 = 1
  *            HSI clock division factor      = 1
  *            HSI Frequency(Hz)              = 16000000
  *            Flash Latency(WS)              = 2
  *            PLLM                           = 1
  *            PLLN                           = 8
  *            PLLP                           = 4
  *            PLLQ                           = 2
  *            PLLR                           = 2
  * @param  None
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};

  /* Select HSI Oscillator as PLL source */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.HSIState       = RCC_HSI_ON;
  RCC_OscInitStruct.PLL.PLLState   = RCC_PLL_ON;


  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    /* Initialization Error */
    while (1);
  }

  /* Select PLL as system clock source and configure the HCLK and PCLK1 clocks dividers */
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_PCLK1);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    /* Initialization Error */
    while (1);
  }
}



/**
 * @brief ���ղ���֤��ȫ����
 */
//int receive_and_verify_secure_packet(const uint8_t *packet, uint8_t *decrypted_payload) {
//    

//    // 1. ��֤MAC��ʹ�ý��յ���IV�����ģ���ͬ������Կ���¼���MAC��������յ���MAC�Ƚ�
//    if (cmox_mac_verify(CMOX_KMAC_128_ALGO, (uint8_t*)packet, IV_LEN + PLAINTEXT_LEN,
//                        session_key, sizeof(session_key), NULL, 0,
//                        received_tag, MAC_LEN) != CMOX_MAC_SUCCESS) {
//        return -1; // MAC��֤ʧ��
//    }

//    // 2. MAC��֤�ɹ��󣬽�������
//    if (cmox_cipher_decrypt(CMOX_SM4_CTR_DEC_ALGO, ciphertext, PLAINTEXT_LEN,
//                            session_key, sizeof(session_key), iv, IV_LEN,
//                            decrypted_payload, &ignored_len) != CMOX_CIPHER_SUCCESS) {
//        return -2; // ����ʧ��
//    }

//    return 0; // �ɹ�
//}



#ifdef USE_FULL_ASSERT

/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {}
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
  

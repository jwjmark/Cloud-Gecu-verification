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
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to hash are processed by chunk */
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/

const uint8_t IV[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
uint8_t Plaintext[8] ;
//809 848 1087 1088 1264


const uint8_t Expected_Ciphertext[] =
{
  0xAC, 0x32, 0x36, 0xCB, 0x97
};

const uint8_t Expected_Tag[] =
{
  0x51, 0xF0, 0xBE
};

const uint8_t KMAC_Key[] =
{
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
};
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
    
    delay_ms(2000);
    
    
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
        // 2. �������ģ��õ�5�ֽ�����
        uint8_t my_ciphertext[5];
        retval = cmox_cipher_encrypt(CMOX_SM4_CTR_ENC_ALGO,
                                     Plaintext, sizeof(Plaintext),
                                     session_key, sizeof(session_key),
                                     IV, sizeof(IV),
                                     my_ciphertext, &computed_size);

        // 3. ��5�ֽڵ����ļ���3�ֽڵ�MAC
        uint8_t my_mac[sizeof(Expected_Tag)];
      retval = cmox_mac_compute(CMOX_CMAC_AES_ALGO,        /* Use AES CMAC algorithm */
                        my_ciphertext, sizeof(my_ciphertext),  /* Message to authenticate */
                        session_key, sizeof(session_key),          /* AES key to use */
                        NULL, 0,                   /* Custom data */
                        my_mac,                 /* Data buffer to receive generated authnetication tag */
                        sizeof(Expected_Tag),      /* Expected authentication tag size */
                        &computed_size);           /* Generated tag size */
        
        // 4. �����ĺ�MACƴ�ӳ�һ��8�ֽڵ�CAN����
        uint8_t can_payload[8];
        memcpy(can_payload, my_ciphertext, 5);
        memcpy(can_payload + 5, my_mac, 3);
        
        // 5. �������8�ֽڵı���
        res = can_send_msg(TARGET_ECU_CAN_ID, can_payload, 8);
        if (res == 0) {
            printf("Message sent successfully.\n");
        } else {
            printf("Message sending failed.\n");
        }


        /*****************************************************************
         * ǿ�Ƶȴ����ս׶� (��JSON����֡)
         *****************************************************************/
        printf("--- Entering Blocking Receive Phase ---\n");

        IRQflag = 0; // �����־λ
        
        while (IRQflag == 0)
        {
            ecu_handle_can_receive();
            delay_ms(5); 
        }

        printf("<-- Received a message! Processing... -->\n");

        // data_buffer �������ǶԷ�������8�ֽ�ԭʼ����
        uint8_t received_ciphertext[5] = {0};
        uint8_t received_mac[3];
        uint8_t computed_mac[3];
        memcpy(received_ciphertext, data_buffer, 5);
        memcpy(received_mac, data_buffer + 5, 3);

        retval = cmox_mac_verify(CMOX_CMAC_AES_ALGO,        /* Use AES CMAC algorithm */
                       received_ciphertext, sizeof(received_ciphertext),  /* Message to authenticate */
                       session_key, sizeof(session_key),          /* AES key to use */
                       NULL, 0,                   /* Custom data */
                       received_mac,              /* Authentication tag */
                       sizeof(Expected_Tag));     /* tag size */

          /* Verify API returned value */
          if (retval == CMOX_MAC_AUTH_SUCCESS)
        {
            printf("MAC Verification SUCCESS!\n");
            LED0_TOGGLE();

            // 2. ����
            uint8_t decrypted_plaintext[5];
            retval = cmox_cipher_decrypt(CMOX_SM4_CTR_DEC_ALGO,
                                        received_ciphertext, sizeof(received_ciphertext),
                                        session_key, sizeof(session_key),
                                        IV, sizeof(IV),
                                        decrypted_plaintext, &computed_size);

            printf("Decryption successful. Decrypted Plaintext: ");
            for (int i = 0; i < 5; i++) {
                printf("0x%02X ", decrypted_plaintext[i]);
            }
            printf("\n");
        }
        else
        {
            printf("!!! MAC Verification FAILED !!! retval=0x%02X\n", retval);
        }
        
        printf("--- Cycle complete. Waiting for next cycle. ---\n");
        delay_ms(20); 
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
  

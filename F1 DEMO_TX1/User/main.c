#include <string.h>
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
/* SM3 context handle */
cmox_sm3_handle_t sm3_ctx;
cmox_kmac_handle_t Kmac_Ctx;
cmox_ctr_handle_t Ctr_Ctx;

__IO TestStatus glob_status = FAILED;

// 全局变量
volatile EcuState g_ecu_state = STATE_WAIT_AUTH_DONE;
uint8_t session_key[16];          // 用于存储从GECU接收的16字节会话密钥



extern uint8_t IRQflag;      // 数据接收完成标志位
extern uint8_t data_buffer;  // 数据缓冲区
extern uint8_t buffer_index; // 当前数据写入位置

/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to hash are processed by chunk */
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/** Extract from IETF draft-oscca-cfrg-sm3-02
  * A.2.  Example 2, From GB/T 32905-2016

   This is example 2 provided by [GBT.32905-2016] to demonstrate hashing
   of a 512-bit plaintext.

A.2.1.  512-bit Input Message

 61626364 61626364 61626364 61626364 61626364 61626364 61626364 61626364
 61626364 61626364 61626364 61626364 61626364 61626364 61626364 61626364

...

A.2.3.  Hash Value

 debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

  */
  
  
 uint8_t Key_Line[4][16] =
{
   {0xe3, 0x10, 0x4d, 0xd3, 0xed, 0x8d, 0x52, 0xd2, 0x50, 0x57, 0x1c, 0xc8, 0xaa, 0x23, 0xf1, 0xbb},
   {0xfa, 0xc3, 0xff, 0xad, 0x9a, 0xf8, 0x78, 0x7f, 0x72, 0xe4, 0xf7, 0x56, 0x5b, 0x7f, 0x00, 0x00},
   {0x44, 0x72, 0xb2, 0x48, 0xdd, 0x45, 0x5a, 0x15, 0x1f, 0xb4, 0xf1, 0x5d, 0x09, 0x31, 0x40, 0x90},
   {0xaf, 0x98, 0xae, 0xb7, 0x38, 0xb9, 0xb1, 0xa5, 0x49, 0xc8, 0xc4, 0x94, 0x36, 0xa4, 0xee, 0x90}
};

uint8_t KMAC_Key_Line[4][32] =
{
    {0x34, 0x6f, 0x63, 0xcf, 0xc1, 0x39, 0x7b, 0xca, 0xd4, 0x64, 0xa8, 0x63, 0x1d, 0x52, 0x39, 0x9e, 
     0xfe, 0x48, 0x59, 0xa5, 0x6b, 0xa8, 0xae, 0xbf, 0x7f, 0x8a, 0x3d, 0x14, 0x27, 0x0c, 0x17, 0x25},
    {0x60, 0x55, 0xc4, 0xfa, 0xb1, 0xfe, 0xe2, 0x96, 0x62, 0xb0, 0xe8, 0xfe, 0x77, 0xf2, 0x8e, 0x9f, 
     0xdf, 0xa2, 0x10, 0x00, 0xc0, 0xdb, 0x07, 0x61, 0x9b, 0xd6, 0xa8, 0x60, 0x3b, 0x13, 0x40, 0xf1},
    {0x79, 0xbf, 0xd0, 0x9c, 0xb0, 0xf3, 0x34, 0xcb, 0x97, 0xcd, 0x1a, 0x6b, 0xca, 0xad, 0x9a, 0x09, 
     0xb8, 0x4d, 0x57, 0x76, 0xec, 0xd3, 0xcc, 0x25, 0xf8, 0x16, 0x9a, 0xa4, 0x5c, 0xef, 0x62, 0x68},
    {0x5d, 0xed, 0xfe, 0xb7, 0x90, 0xad, 0x81, 0x8e, 0x43, 0x4c, 0xee, 0xb8, 0xce, 0x2a, 0xe3, 0x09, 
     0x25, 0x42, 0x2d, 0x92, 0xf7, 0xc1, 0x14, 0x27, 0x24, 0x34, 0xa4, 0xd7, 0xb7, 0x1b, 0x60, 0x43}
};
const uint8_t IV[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
const uint8_t Plaintext[4][8] =
{
{0x87, 0xB9, 0x7E, 0x14, 0x12, 0x20, 0x00, 0x14},
{0xDC, 0xB9, 0x7E, 0x14, 0x12, 0x20, 0x00, 0x14},
{0x0C, 0xB9, 0x7E, 0x14, 0x12, 0x20, 0x00, 0x14},
{0x40, 0xB9, 0x7E, 0x14, 0x12, 0x20, 0x00, 0x14}
};
//809 848 1087 1088 1264

//const uint32_t testID[5]={0x350, 0x329, 0x43F, 0x440, 0x4F0};

//, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB

const uint8_t Expected_Ciphertext[] =
{
  0xAC, 0x32, 0x36, 0xCB, 0x97, 0x0C
};
//, 0x91, 0x36, 0x4C, 0x39, 0x5A, 0x13, 0x42, 0xD1

const uint8_t Expected_Tag[] =
{
  0x4E, 0x6C
};


const uint8_t Custom_Data[21] = "My Tagged Application";


/* Computed data buffer */
uint8_t Computed_Ciphertext[sizeof(Expected_Ciphertext)];
uint8_t Computed_Plaintext[sizeof(Plaintext)];
uint8_t Computed_Tag[sizeof(Expected_Tag)];


/* Private function prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
static void Error_Handler(void);

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
   
    
    uint8_t Key[16];
    uint8_t KMAC_Key[32];
    uint8_t KMAC_tag = 1;
    memcpy(KMAC_Key, KMAC_Key_Line[0], 32);
    
    uint8_t i = 0, t = 0;
    
    int cnt = 0;
    uint8_t canbuf[]= "abcdefghijklmn";
    int btest = strlen((char *)canbuf);
    uint8_t rxbuf[8]={1,1,1,1,1,1,1,1};
    uint8_t rxlen = 0;
    uint8_t res = 0;
    uint8_t mode = 0; /* CAN工作模式: 0,普通模式; 1,环回模式 */


    HAL_Init();                                                            /* 初始化HAL库 */
    sys_stm32_clock_init(RCC_PLL_MUL9);                                    /* 设置时钟, 72Mhz */
    delay_init(72);                                                        /* 延时初始化 */
    usart_init(115200);                                                    /* 串口初始化为115200 */
    usmart_dev.init(72);                                                   /* 初始化USMART */
    led_init();                                                            /* 初始化LED */
//    lcd_init();                                                          /* 初始化LCD */
//    key_init();                                                          /* 初始化按键 */
    can_init(CAN_SJW_1TQ, CAN_BS2_8TQ, CAN_BS1_9TQ, 4, CAN_MODE_NORMAL);   /* CAN初始化, 普通模式, 波特率500Kbps */
            
    //memset(canbuf,0,sizeof(canbuf));
//    res = can_send_msg(0X11, canbuf, 8); /* 发送ID = 0X12, 发送8个字节 */

  /* --------------------------------------------------------------------------
   * SINGLE CALL USAGE
   * --------------------------------------------------------------------------
   */
   
   
   while(1)
   {
       ecu_handle_can_receive();
//       switch (g_ecu_state)
//       {
//           case STATE_WAIT_AUTH_DONE:
//               delay_ms(100);
//           break;
//           
//           case STATE_SECURE_MODE:
//               delay_ms(100);
//           break;
//           
//           case STATE_ERROR:
//               delay_ms(100);
//           break;
//       }
       delay_ms(10);
           
           
   }
   
//   
//    unsigned char buffer[16];
//    memset(buffer, 1, 16);
//    can_send_msg(0x01, buffer, 16);
   

  /* Compute directly the ciphertext passing all the needed parameters */
    while(cnt <= 200){            
            if (cnt < 200) {
                memcpy(Key, Key_Line[cnt / 50], 16);  // 按段加载 Key
            }else if (cnt == 200) {
                if (KMAC_tag > 3) {
                    while(1)
                    {
                        LED0_TOGGLE();
                    }
                }else{
                    memcpy(KMAC_Key, Key_Line[KMAC_tag], 32);
                    KMAC_tag++;
                    cnt = 0;
                }
            }
            for(int j=0; j<4; j++){
                retval = cmox_cipher_encrypt(CMOX_SM4_CTR_ENC_ALGO,                  /* Use SM4 CTR algorithm */
                                           Plaintext[j], sizeof(Plaintext[j]),           /* Plaintext to encrypt */
                                           Key, sizeof(Key),                       /* AES key to use */
                                           IV, sizeof(IV),                         /* Initialization vector */
                                           Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated ciphertext */
                                           
            //    can_send_msg(0x12, (uint8_t *)Computed_Ciphertext, 8);
                                           
                 /* Compute directly the authentication tag passing all the needed parameters */
                retval = cmox_mac_compute(CMOX_KMAC_128_ALGO,               /* Use KMAC 128 algorithm */
                                        Plaintext[j], sizeof(Plaintext[j]),         /* Message to authenticate */
                                        KMAC_Key, sizeof(KMAC_Key),                 /* KMAC Key to use */
                                        Custom_Data, sizeof(Custom_Data), /* Custom data */
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
                                           
                
                cJSON *object = cJSON_CreateObject();    //创建JSON指针头结点

                cJSON_AddStringToObject(object, "PDU", str_pdu);
                
                cJSON_AddStringToObject(object, "MAC", str_mac);

                char *jsonString = cJSON_Print(object);  // 将JSON对象转换为字符串
                    printf("JSON字符串是什么样的：%s\n",jsonString);
                
                int jsonstirnglen= strlen(jsonString);
    //                printf("发送数据长度：%d\n",jsonstirnglen);
                for(int times=0; times <4; times++)
                {
                    res = can_send_msg(CAN_ID_ECU3,(unsigned char *)jsonString, jsonstirnglen);
                    HAL_Delay(2500);
                }
                cJSON_Delete(object);object = NULL;
                free(jsonString);
            }
            cnt++;
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
  * @brief  This function is executed in case of error occurrence
  * @param  None
  * @retval None
  */
static void Error_Handler(void)
{
  /* User may add here some code to deal with this error */
  /* Toggle LED4 @2Hz to notify error condition */
  while (1)
  {
//    BSP_LED_Toggle(LED4);
    HAL_Delay(250);
  }
}

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
  

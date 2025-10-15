#include <string.h>
#include <stdlib.h>
#include "./BSP/CAN/can.h"
#include "./BSP/CAN/can_config.h"
#include "./BSP/LED/led.h"
#include "./SYSTEM/delay/delay.h"
#include "./SYSTEM/usart/usart.h"


#define MAX_CAN_FRAME_SIZE 8  // ����CAN֡������ݳ���Ϊ8�ֽ�
#define MAX_DATA_BUFFER_SIZE 512  // ����������ݳ���Ϊ64�ֽ�
#define SINGLE_FRAME 0x31     // ��֡��ʶ
#define START_FRAME 0x10      // ����֡��ʶ
#define DATA_FRAME 0x21       // ����֡��ʶ
#define END_FRAME 0x22        // ����֡��ʶ

extern volatile EcuState g_ecu_state;
extern uint8_t session_key[32];


uint8_t data_buffer[MAX_DATA_BUFFER_SIZE];  // ���ݻ�����
uint16_t buffer_index = 0;                 // ��ǰ����д��λ��
volatile uint8_t IRQflag = 0;                     // ����״̬��־
uint32_t rx_id = CAN_ID_GATEWAY_STATUS;


CAN_HandleTypeDef   g_canx_handler;     /* CANx��� */
CAN_TxHeaderTypeDef g_canx_txheader;    /* ���Ͳ������ */
CAN_RxHeaderTypeDef g_canx_rxheader;    /* ���ղ������ */

/**
 * @brief       CAN��ʼ��
 * @param       tsjw    : ����ͬ����Ծʱ�䵥Ԫ.��Χ: 1~3;
 * @param       tbs2    : ʱ���2��ʱ�䵥Ԫ.��Χ: 1~8;
 * @param       tbs1    : ʱ���1��ʱ�䵥Ԫ.��Χ: 1~16;
 * @param       brp     : �����ʷ�Ƶ��.��Χ: 1~1024;
 *   @note      ����4������, �ں����ڲ����1, ����, �κ�һ�����������ܵ���0
 *              CAN����APB1����, ������ʱ��Ƶ��Ϊ Fpclk1 = PCLK1 = 36Mhz
 *              tq     = brp * tpclk1;
 *              ������ = Fpclk1 / ((tbs1 + tbs2 + 1) * brp);
 *              �������� can_init(1, 8, 9, 4, 1), ��CAN������Ϊ:
 *              36M / ((8 + 9 + 1) * 4) = 500Kbps
 *
 * @param       mode    : CAN_MODE_NORMAL,  ��ͨģʽ;
                          CAN_MODE_LOOPBACK,�ػ�ģʽ;
 * @retval      0,  ��ʼ���ɹ�; ����, ��ʼ��ʧ��;
 */
uint8_t can_init(uint32_t tsjw, uint32_t tbs2, uint32_t tbs1, uint16_t brp, uint32_t mode)
{
  g_canx_handler.Instance = CAN1;
  g_canx_handler.Init.Prescaler = brp;                /* ��Ƶϵ��(Fdiv)Ϊbrp+1 */
  g_canx_handler.Init.Mode = mode;                    /* ģʽ���� */
  g_canx_handler.Init.SyncJumpWidth = tsjw;           /* ����ͬ����Ծ���(Tsjw)Ϊtsjw+1��ʱ�䵥λ CAN_SJW_1TQ~CAN_SJW_4TQ */
  g_canx_handler.Init.TimeSeg1 = tbs1;                /* tbs1��ΧCAN_BS1_1TQ~CAN_BS1_16TQ */
  g_canx_handler.Init.TimeSeg2 = tbs2;                /* tbs2��ΧCAN_BS2_1TQ~CAN_BS2_8TQ */
  g_canx_handler.Init.TimeTriggeredMode = DISABLE;    /* ��ʱ�䴥��ͨ��ģʽ */
  g_canx_handler.Init.AutoBusOff = DISABLE;           /* ����Զ����߹��� */
  g_canx_handler.Init.AutoWakeUp = DISABLE;           /* ˯��ģʽͨ���������(���CAN->MCR��SLEEPλ) */
  g_canx_handler.Init.AutoRetransmission = ENABLE;    /* ��ֹ�����Զ����� */
  g_canx_handler.Init.ReceiveFifoLocked = DISABLE;    /* ���Ĳ�����,�µĸ��Ǿɵ� */
  g_canx_handler.Init.TransmitFifoPriority = DISABLE; /* ���ȼ��ɱ��ı�ʶ������ */
  if (HAL_CAN_Init(&g_canx_handler) != HAL_OK)        //HAL_CAN_Init��ʼ��CAN������ͬʱ�а�����HAL_CAN_MspInit���Գ�ʼ��CAN�ײ�
  {
    return 1;
  }

#if CAN_RX0_INT_ENABLE

  /* ʹ���жϽ��� */
  __HAL_CAN_ENABLE_IT(&g_canx_handler, CAN_IT_RX_FIFO0_MSG_PENDING); /* FIFO0��Ϣ�Һ��ж����� */
  HAL_NVIC_EnableIRQ(USB_LP_CAN1_RX0_IRQn);                          /* ʹ��CAN�ж� */
  HAL_NVIC_SetPriority(USB_LP_CAN1_RX0_IRQn, 1, 0);                  /* ��ռ���ȼ�1�������ȼ�0 */
#endif

  CAN_FilterTypeDef sFilterConfig;

  /*����CAN������*/
  sFilterConfig.FilterBank = 0;                             /* ������0 */
  sFilterConfig.FilterMode = CAN_FILTERMODE_IDMASK;         
  sFilterConfig.FilterScale = CAN_FILTERSCALE_32BIT;
  sFilterConfig.FilterIdHigh = 0x0000;                      /* 32λID */
  sFilterConfig.FilterIdLow = 0x0000;
  sFilterConfig.FilterMaskIdHigh = 0x0000;                  /* 32λMASK */
  sFilterConfig.FilterMaskIdLow = 0x0000;
  sFilterConfig.FilterFIFOAssignment = CAN_FILTER_FIFO0;    /* ������0������FIFO0 */
  sFilterConfig.FilterActivation = CAN_FILTER_ENABLE;       /* �����˲���0 */
  sFilterConfig.SlaveStartFilterBank = 14;

  /* ���������� */
  if (HAL_CAN_ConfigFilter(&g_canx_handler, &sFilterConfig) != HAL_OK)
  {
    return 2;
  }

  /* ����CAN��Χ�豸 */
  if (HAL_CAN_Start(&g_canx_handler) != HAL_OK)
  {
    return 3;
  }


  return 0;
}

/**
 * @brief       CAN�ײ��������������ã�ʱ�����ã��ж�����
                �˺����ᱻHAL_CAN_Init()����
 * @param       hcan:CAN���
 * @retval      ��
 */
void HAL_CAN_MspInit(CAN_HandleTypeDef *hcan)
{
  if (CAN1 == hcan->Instance)
  {
    CAN_RX_GPIO_CLK_ENABLE();       /* CAN_RX��ʱ��ʹ�� */
    CAN_TX_GPIO_CLK_ENABLE();       /* CAN_TX��ʱ��ʹ�� */
    __HAL_RCC_CAN1_CLK_ENABLE();    /* ʹ��CAN1ʱ�� */

    GPIO_InitTypeDef gpio_initure;

    gpio_initure.Pin = CAN_TX_GPIO_PIN;
    gpio_initure.Mode = GPIO_MODE_AF_PP;
    gpio_initure.Pull = GPIO_PULLUP;
    gpio_initure.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(CAN_TX_GPIO_PORT, &gpio_initure); /* CAN_TX�� ģʽ���� */

    gpio_initure.Pin = CAN_RX_GPIO_PIN;
    gpio_initure.Mode = GPIO_MODE_AF_INPUT;
    HAL_GPIO_Init(CAN_RX_GPIO_PORT, &gpio_initure); /* CAN_RX�� �������ó�����ģʽ */
  }
}

#if CAN_RX0_INT_ENABLE /* ʹ��RX0�ж� */

/**
 * @brief       CAN RX0 �жϷ�����
 *   @note      ����CAN FIFO0�Ľ����ж�
 * @param       ��
 * @retval      ��
 */
void USB_LP_CAN1_RX0_IRQHandler(void)
{
    
    IRQflag = 0;

    uint8_t rxbuf[8];
    uint32_t id = 0x104;
    can_receive_msg(id, rxbuf);
    printf("id %x\n", id);
    printf("\n 111111111111111111111111111111 \n");

    uint8_t frame_type = rxbuf[0];  // ��ȡ֡���ͱ�ʶ��
    uint8_t* frame_data = &rxbuf[1]; // ��ȡ���ݲ���

    static uint8_t data_len =  7 ;    // ���ݳ��ȣ�ȥ����ʶ����
    printf("data_len = %d \n",data_len);
       switch (frame_type) {
            case SINGLE_FRAME:
                // ��ֱ֡�Ӵ���
                memcpy(data_buffer, frame_data, data_len);
                buffer_index = data_len;
                IRQflag = 1;  // ��������
                printf("IRQflag��־λΪ��%d:",IRQflag);
                ProcessData(data_buffer, buffer_index);  // �������ݴ�����
                printf("��֡����");
                break;

            case START_FRAME:
                // ����֡����ʼ��������
                memset(data_buffer, 0, MAX_DATA_BUFFER_SIZE);
                buffer_index = 0;
                memcpy(&data_buffer[buffer_index], frame_data, data_len);
                buffer_index += data_len;
                IRQflag = 0;  // ��ʼ���ն�֡
                printf("����֡����");
                break;

            case DATA_FRAME:
                // ����֡���ۼӵ�������
                if (buffer_index + data_len <= MAX_DATA_BUFFER_SIZE) {
                    memcpy(&data_buffer[buffer_index], frame_data, data_len);
                    buffer_index += data_len;
                    printf("����֡����");
                }
                break;

            case END_FRAME:
                // ����֡����ɽ���
                if (buffer_index + data_len <= MAX_DATA_BUFFER_SIZE) {
                    memcpy(&data_buffer[buffer_index], frame_data, data_len);
                    for (int i = 0; i < 22; i++) {
                    printf("data_buffer[%d] = 0x%02X\n", i, data_buffer[i]);
                    }
                    buffer_index += data_len;
                    IRQflag = 1;  // ��������
                    printf("IRQflag��־λΪ��%d:\n",IRQflag);
                    printf("����֡����\n");
                }
                break;

            default:
                // δ֪֡���ͣ�����
                break;
        }
    
}

#endif

/**
 * @brief       ������յ�����������(������ӵĴ�����)
 * @note        �ú����ڽ��յ������Ķ�֡CAN��Ϣ����ã�
 *              ���޳���ʶ������������ϲ������
 * @param       data    : ָ����յ������ݻ�������ָ��
 * @param       length  : ���ݳ��ȣ��ֽ�����
 * @retval      ��
 */
char* ProcessData(uint8_t* data, uint16_t length) {
    
    printf("Received data (%d bytes):\n", length);
    for (uint16_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
    }

    char str_received[sizeof(data) * 2 + 1];  // 2 characters per byte + null terminator
    for (int i = 0; i < sizeof(data); i++) 
    {
        sprintf(&str_received[i * 2], "%02x", data[i]);
    }
    str_received[sizeof(data) * 2] = '\0';  // Null-terminate the string

    return str_received;  // �����ַ���ָ��

}


/**
 * @brief       CAN ����һ������
 *   @note      ���͸�ʽ�̶�Ϊ: ��׼ID, ����֡
 * @param       id      : ��׼ID(11λ)
 * @retval      ����״̬ 0, �ɹ�; 1, ʧ��;
 */
uint8_t can_send_msg(uint32_t id, uint8_t *msg, uint8_t len)
{
    uint32_t TxMailbox = CAN_TX_MAILBOX0;
    g_canx_txheader.StdId = id;
    g_canx_txheader.IDE = CAN_ID_STD;
    g_canx_txheader.RTR = CAN_RTR_DATA;

    // === �����߼����ж��Ƿ�Ϊ��ȫECU��Ϣ ===
    // �����ECU��İ�ȫ��Ϣ������ֱ�ӷ���8�ֽڣ������κ�Э��ͷ
    if (id >= CAN_ID_ECU_MSG_BASE && len == 8)
    {
        g_canx_txheader.DLC = 8;
        if (HAL_CAN_AddTxMessage(&g_canx_handler, &g_canx_txheader, msg, &TxMailbox) != HAL_OK)
        {
            return 1; // ����ʧ��
        }
        while (HAL_CAN_GetTxMailboxesFreeLevel(&g_canx_handler) != 3); // �ȴ��������
        return 0; // ���ͳɹ�
    }

    // === ����ԭ�еĶ�֡�߼���������Կ�ַ� ===
    uint8_t TxData[MAX_CAN_FRAME_SIZE];
    if (len <= 7)
    {
        TxData[0] = SINGLE_FRAME;
        memcpy(&TxData[1], msg, len);
        g_canx_txheader.DLC = len + 1;
        if (HAL_CAN_AddTxMessage(&g_canx_handler, &g_canx_txheader, TxData, &TxMailbox) != HAL_OK)
        {
            return 1;
        }
        while (HAL_CAN_GetTxMailboxesFreeLevel(&g_canx_handler) != 3);
    }
    else
    {
        uint8_t offset = 0;
        uint8_t remaining_len = len;
        uint8_t frame_type = START_FRAME;
        
        while (remaining_len > 0)
        {
            uint8_t current_frame_len = remaining_len > MAX_CAN_FRAME_SIZE - 1 ? MAX_CAN_FRAME_SIZE - 1 : remaining_len;
            
            TxData[0] = frame_type;
            memcpy(&TxData[1], &msg[offset], current_frame_len);
            g_canx_txheader.DLC = current_frame_len + 1;
            
            if (HAL_CAN_AddTxMessage(&g_canx_handler, &g_canx_txheader, TxData, &TxMailbox) != HAL_OK)
            {
                return 1;
            }
            
            while (HAL_CAN_GetTxMailboxesFreeLevel(&g_canx_handler) != 3);
            
            offset += current_frame_len;
            remaining_len -= current_frame_len;
            
            if (remaining_len > 0)
            {
                frame_type = (remaining_len > (MAX_CAN_FRAME_SIZE - 1)) ? DATA_FRAME : END_FRAME;
            }
        }
    }
    return 0;
}

/**
 * @brief       CAN �������ݲ�ѯ
 *   @note      �������ݸ�ʽ�̶�Ϊ: ��׼ID, ����֡
 * @param       id      : Ҫ��ѯ�� ��׼ID(11λ)
 * @param       buf     : ���ݻ�����
 * @retval      ���ս��
 *   @arg       0   , �����ݱ����յ�;
 *   @arg       ����, ���յ����ݳ���
 */
uint8_t can_receive_msg(uint8_t *buf)
{
  if (HAL_CAN_GetRxFifoFillLevel(&g_canx_handler, CAN_RX_FIFO0) == 0)     /* û�н��յ����� */
  {
    return 0;
  }

  if (HAL_CAN_GetRxMessage(&g_canx_handler, CAN_RX_FIFO0, &g_canx_rxheader, buf) != HAL_OK)  /* ��ȡ���� */
  {
    return 0;
  }
  
//  if (g_canx_rxheader.StdId!= id || g_canx_rxheader.IDE != CAN_ID_STD || g_canx_rxheader.RTR != CAN_RTR_DATA)       /* ���յ���ID���� / ���Ǳ�׼֡ / ��������֡ */
//  {
//    return 0;    
//  }

  return g_canx_rxheader.DLC;

}

/**
 * @brief ���ĺ���������CAN���߽��յ�����Ϣ
 */
// ��ԭ���� ecu_handle_can_receive ������ȫ�滻Ϊ���°汾
void ecu_handle_can_receive(void)
{
    uint8_t rxlen = 0;
    uint8_t rxbuf[8];
    
    // �����޸ĺ�Ľ��պ������������ g_canx_rxheader
    rxlen = can_receive_msg(rxbuf); 

    if (rxlen > 0)
    {
        // ��ȫ�ֱ��� g_canx_rxheader �л�ȡʵ�ʽ��յ���ID
        uint32_t received_id = g_canx_rxheader.StdId; 
        
        uint8_t frame_type = rxbuf[0];
        uint8_t* frame_data = &rxbuf[1];
        // �������ؼ��޸�������ʵ��DLC�������ݳ��ȣ�����
        uint8_t data_len = rxlen - 1; 

        // ���ݽ��յ���ID��������δ�������
        if (received_id == MY_ECU_KEY_ID)
        {
            switch (frame_type) {
                case START_FRAME:
                    memset(data_buffer, 0, MAX_DATA_BUFFER_SIZE);
                    buffer_index = 0;
                    if (data_len > 0) {
                        memcpy(&data_buffer[buffer_index], frame_data, data_len);
                        buffer_index += data_len;
                    }
                    IRQflag = 0;
                    break;

                case DATA_FRAME:
                    if (buffer_index + data_len <= MAX_DATA_BUFFER_SIZE) {
                         if (data_len > 0) {
                           memcpy(&data_buffer[buffer_index], frame_data, data_len);
                           buffer_index += data_len;
                        }
                    }
                    break;

                case END_FRAME:
                    if (buffer_index + data_len <= MAX_DATA_BUFFER_SIZE) {
                        if (data_len > 0) {
                            memcpy(&data_buffer[buffer_index], frame_data, data_len);
                            buffer_index += data_len;
                        }
                        
                        printf("Total key length received: %d bytes.\n", buffer_index);
                        for (int i = 0; i < 16; i++) {
                            // ֻ����Ч�����ڿ���
                            if (i < buffer_index) {
                                session_key[i] = data_buffer[i];
                            } else {
                                session_key[i] = 0; // �����Կ���Ȳ���16������0���
                            }
                            printf("session_key[%d] = 0x%02X\n", i, session_key[i]);
                        }
                        
                        g_ecu_state = STATE_SECURE_MODE;
                        IRQflag = 1;
                    }
                    break;
                
                default:
                    // δ֪֡���ͣ�����״̬
                    buffer_index = 0;
                    IRQflag = 0;
                    break;
            }
        }
        else if (received_id == MY_ECU_RX_CAN_ID)
        {
            memcpy(data_buffer, rxbuf, 8); // ֱ�ӿ���8�ֽ�����
            IRQflag = 1; // ���ñ�־λ
            return; // ������ϣ�ֱ�ӷ���
        }
    }
}

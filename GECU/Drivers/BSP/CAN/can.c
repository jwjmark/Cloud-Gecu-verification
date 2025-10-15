#include <string.h>
#include <stdlib.h>
#include "ctype.h"
#include "./BSP/CAN/can.h"
#include "./BSP/CAN/can_config.h"
#include "./BSP/LED/led.h"
#include "./SYSTEM/delay/delay.h"
#include "./SYSTEM/usart/usart.h"


#define MAX_CAN_FRAME_SIZE 8  // 单个CAN帧最大数据长度为8字节
#define MAX_DATA_BUFFER_SIZE 256  // 假设最大数据长度为256字节
#define SINGLE_FRAME 0x31     // 单帧标识
#define START_FRAME 0x10      // 启动帧标识
#define DATA_FRAME 0x21       // 数据帧标识
#define END_FRAME 0x22        // 结束帧标识

char str_received[256];
uint8_t data_buffer[MAX_DATA_BUFFER_SIZE];  // 数据缓冲区
uint16_t buffer_index = 0;                 // 当前数据写入位置
volatile uint8_t IRQflag = 0;                     // 接收状态标志


CAN_HandleTypeDef   g_canx_handler;     /* CANx句柄 */
CAN_TxHeaderTypeDef g_canx_txheader;    /* 发送参数句柄 */
CAN_RxHeaderTypeDef g_canx_rxheader;    /* 接收参数句柄 */

/**
 * @brief       CAN初始化
 * @param       tsjw    : 重新同步跳跃时间单元.范围: 1~3;
 * @param       tbs2    : 时间段2的时间单元.范围: 1~8;
 * @param       tbs1    : 时间段1的时间单元.范围: 1~16;
 * @param       brp     : 波特率分频器.范围: 1~1024;
 *   @note      以上4个参数, 在函数内部会减1, 所以, 任何一个参数都不能等于0
 *              CAN挂在APB1上面, 其输入时钟频率为 Fpclk1 = PCLK1 = 42Mhz
 *              tq     = brp * tpclk1;
 *              波特率 = Fpclk1 / ((tbs1 + tbs2 + 1) * brp);
 *              我们设置 can_init(1, 6, 7, 6, 1), 则CAN波特率为:
 *              42M / ((6 + 7 + 1) * 6) = 500Kbps
 *
 * @param       mode    : CAN_MODE_NORMAL,  普通模式;
                          CAN_MODE_LOOPBACK,回环模式;
 * @retval      0,  初始化成功; 其他, 初始化失败;
 */
uint8_t can_init(uint32_t tsjw, uint32_t tbs2, uint32_t tbs1, uint16_t brp, uint32_t mode)
{
    g_canx_handler.Instance = CAN1;
    g_canx_handler.Init.Prescaler = brp;                /* 分频系数(Fdiv)为brp+1 */
    g_canx_handler.Init.Mode = mode;                    /* 模式设置 */
    g_canx_handler.Init.SyncJumpWidth = tsjw;           /* 重新同步跳跃宽度(Tsjw)为tsjw+1个时间单位 CAN_SJW_1TQ~CAN_SJW_4TQ */
    g_canx_handler.Init.TimeSeg1 = tbs1;                /* tbs1范围CAN_BS1_1TQ~CAN_BS1_16TQ */
    g_canx_handler.Init.TimeSeg2 = tbs2;                /* tbs2范围CAN_BS2_1TQ~CAN_BS2_8TQ */
    g_canx_handler.Init.TimeTriggeredMode = DISABLE;    /* 非时间触发通信模式 */
    g_canx_handler.Init.AutoBusOff = DISABLE;           /* 软件自动离线管理 */
    g_canx_handler.Init.AutoWakeUp = DISABLE;           /* 睡眠模式通过软件唤醒(清除CAN->MCR的SLEEP位) */
    g_canx_handler.Init.AutoRetransmission = ENABLE;    /* 禁止报文自动传送 */
    g_canx_handler.Init.ReceiveFifoLocked = DISABLE;    /* 报文不锁定,新的覆盖旧的 */
    g_canx_handler.Init.TransmitFifoPriority = DISABLE; /* 优先级由报文标识符决定 */
    if (HAL_CAN_Init(&g_canx_handler) != HAL_OK)
    {
        return 1;
    }

#if CAN_RX0_INT_ENABLE

    /* 使用中断接收 */
    __HAL_CAN_ENABLE_IT(&g_canx_handler, CAN_IT_RX_FIFO0_MSG_PENDING); /* FIFO0消息挂号中断允许 */
    HAL_NVIC_EnableIRQ(CAN1_RX0_IRQn);                                 /* 使能CAN中断 */
    HAL_NVIC_SetPriority(CAN1_RX0_IRQn, 1, 0);                         /* 抢占优先级1，子优先级0 */
#endif

    CAN_FilterTypeDef sFilterConfig;

    /* 配置CAN过滤器 */
    sFilterConfig.FilterBank = 0;                             /* 过滤器0 */
    sFilterConfig.FilterMode = CAN_FILTERMODE_IDMASK;
    sFilterConfig.FilterScale = CAN_FILTERSCALE_32BIT;
    sFilterConfig.FilterIdHigh = 0x0000;                      /* 32位ID */
    sFilterConfig.FilterIdLow = 0x0000;
    sFilterConfig.FilterMaskIdHigh = 0x0000;                  /* 32位MASK */
    sFilterConfig.FilterMaskIdLow = 0x0000;
    sFilterConfig.FilterFIFOAssignment = CAN_FILTER_FIFO0;    /* 过滤器0关联到FIFO0 */
    sFilterConfig.FilterActivation = CAN_FILTER_ENABLE;       /* 激活滤波器0 */
    sFilterConfig.SlaveStartFilterBank = 14;

    /* 过滤器配置 */
    if (HAL_CAN_ConfigFilter(&g_canx_handler, &sFilterConfig) != HAL_OK)
    {
        return 2;
    }

    /* 启动CAN外围设备 */
    if (HAL_CAN_Start(&g_canx_handler) != HAL_OK)
    {
        return 3;
    }


    return 0;
}

/**
 * @brief       CAN底层驱动，引脚配置，时钟配置，中断配置
                此函数会被HAL_CAN_Init()调用
 * @param       hcan:CAN句柄
 * @retval      无
 */
void HAL_CAN_MspInit(CAN_HandleTypeDef *hcan)
{
    if (CAN1 == hcan->Instance)
    {
        CAN_RX_GPIO_CLK_ENABLE();       /* CAN_RX脚时钟使能 */
        CAN_TX_GPIO_CLK_ENABLE();       /* CAN_TX脚时钟使能 */
        __HAL_RCC_CAN1_CLK_ENABLE();    /* 使能CAN1时钟 */

        GPIO_InitTypeDef gpio_init_struct;

        gpio_init_struct.Pin = CAN_TX_GPIO_PIN;
        gpio_init_struct.Mode = GPIO_MODE_AF_PP;
        gpio_init_struct.Pull = GPIO_PULLUP;
        gpio_init_struct.Speed = GPIO_SPEED_FREQ_HIGH;
        gpio_init_struct.Alternate = GPIO_AF9_CAN1;
        HAL_GPIO_Init(CAN_TX_GPIO_PORT, &gpio_init_struct); /* CAN_TX脚 模式设置 */

        gpio_init_struct.Pin = CAN_RX_GPIO_PIN;
        HAL_GPIO_Init(CAN_RX_GPIO_PORT, &gpio_init_struct); /* CAN_RX脚 必须设置成输入模式 */
    }
}

#if CAN_RX0_INT_ENABLE /* 使能RX0中断 */

/**
 * @brief       CAN RX0 中断服务函数
 *   @note      处理CAN FIFO0的接收中断
 * @param       无
 * @retval      无
 */
void CAN1_RX0_IRQHandler(void)
{
    uint8_t rxbuf[8];
    uint32_t id = 0x12;
    can_receive_msg(id, rxbuf);
//    printf("Received: ID=0x%03X, DLC=%d, Data=", g_canx_rxheader.StdId, g_canx_rxheader.DLC);
//    for (int i = 0; i < g_canx_rxheader.DLC; i++) {
//        printf("0x%02X ", rxbuf[i]);
//    }
//    printf("\n");

    uint8_t frame_type = rxbuf[0];  // 提取帧类型标识符
    uint8_t* frame_data = &rxbuf[1]; // 提取数据部分
//    for (int i = 0; i < 8; i++) {
//    printf("rxbuf[%d] = 0x%02X  ", i, rxbuf[i]);
//    }
    static uint8_t data_len =  7 ;    // 数据长度（去掉标识符）
//    printf("data_len = %d",data_len);
       switch (frame_type) {
            case SINGLE_FRAME:
                // 单帧直接处理
                memcpy(data_buffer, frame_data, data_len);
                buffer_index = data_len;
                IRQflag = 1;  // 结束接收
//                printf("IRQflag标志位为：%d:",IRQflag);
                printf("单帧接收%s\n",data_buffer);
                break;

            case START_FRAME:
                // 启动帧，初始化缓冲区
                memset(data_buffer, 0, MAX_DATA_BUFFER_SIZE);
                buffer_index = 0;
                memcpy(&data_buffer[buffer_index], frame_data, data_len);
                buffer_index += data_len;
                IRQflag = 0;  // 开始接收多帧
//                printf("\n启动帧接收\n");
                break;

            case DATA_FRAME:
                // 数据帧，累加到缓冲区
                if (buffer_index + data_len <= MAX_DATA_BUFFER_SIZE) {
                    memcpy(&data_buffer[buffer_index], frame_data, data_len);
                    buffer_index += data_len;
//                    printf("数据帧接收\n");
                }
                break;

            case END_FRAME:
                // 结束帧，完成接收
                if (buffer_index + data_len <= MAX_DATA_BUFFER_SIZE) {                    
                    uint8_t endframelen = 0;
                    for(int a = 6; a >= 0; a--){
                        if(frame_data[a]!=0){
                            endframelen = a+1;
                        break;
                        }
                    }
//                    printf("endframelen:%d\n",endframelen);
                    
                    memcpy(&data_buffer[buffer_index], frame_data, endframelen); 

                    buffer_index += endframelen;
                    data_buffer[buffer_index] = '\0';
//                    for (int i = 0; i < buffer_index; i++) {
//                    printf("data_buffer[%d] = 0x%02X\n", i, data_buffer[i]);
//                    }
                    
//                    printf("结束帧接收:%s\n",data_buffer);
                    
                    IRQflag = 1;  // 结束接收
                }
                break;

            default:
                // 未知帧类型，忽略
                break;
        }
    
//  can_receive_msg(id, rxbuf);
//  printf("id:%d\r\n", g_canx_rxheader.StdId);
//  printf("ide:%d\r\n", g_canx_rxheader.IDE);
//  printf("rtr:%d\r\n", g_canx_rxheader.RTR);
//  printf("len:%d\r\n", g_canx_rxheader.DLC);

//  printf("rxbuf[0]:%d\r\n", rxbuf[0]);
//  printf("rxbuf[1]:%d\r\n", rxbuf[1]);
//  printf("rxbuf[2]:%d\r\n", rxbuf[2]);
//  printf("rxbuf[3]:%d\r\n", rxbuf[3]);
//  printf("rxbuf[4]:%d\r\n", rxbuf[4]);
//  printf("rxbuf[5]:%d\r\n", rxbuf[5]);
//  printf("rxbuf[6]:%d\r\n", rxbuf[6]);
//  printf("rxbuf[7]:%d\r\n", rxbuf[7]);
    
}

#endif

void StringToByte(char* source, uint8_t* dest, int sourceLen)
{
    int i;
    uint8_t highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2)
    {
		highByte = toupper(source[i]);
		lowByte  = toupper(source[i + 1]);

		if (highByte > 0x39)
			highByte -= 0x37;
		else
			highByte -= 0x30;

		if (lowByte > 0x39)
			lowByte -= 0x37;
		else
			lowByte -= 0x30;

		dest[i / 2] = (highByte << 4) | lowByte;
	}
	return ;
}

/**
 * @brief       处理接收到的整合数据(自行添加的处理函数)
 * @note        该函数在接收到完整的多帧CAN消息后调用，
 *              将剔除标识符后的数据整合并输出。
 * @param       data    : 指向接收到的数据缓冲区的指针
 * @param       length  : 数据长度（字节数）
 * @retval      无
 */
void ProcessData(uint8_t* data, uint16_t length, char* str_received) {
    
    printf("Received data (%d bytes):\n", length);
    for (uint16_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
    }
    StringToByte(data, str_received, length);
    printf("\nProcessData:%s\n",str_received);
}




/**
 * @brief       CAN 发送一组数据
 *   @note      发送格式固定为: 标准ID, 数据帧
 * @param       id      : 标准ID(11位)
 * @retval      发送状态 0, 成功; 1, 失败;
 */
uint8_t can_send_msg(uint32_t id, uint8_t *msg, uint8_t len)
{
  uint32_t TxMailbox = CAN_TX_MAILBOX0;
  g_canx_txheader.StdId = id;         /* 标准标识符 */
  g_canx_txheader.ExtId = id;         /* 扩展标识符(29位) */
  g_canx_txheader.IDE = CAN_ID_STD;   /* 使用标准帧 */
  g_canx_txheader.RTR = CAN_RTR_DATA; /* 数据帧 */
  //g_canx_txheader.DLC = len;    
    
    uint8_t TxData[MAX_CAN_FRAME_SIZE];
    if (len <= 7)
    {
        // 如果数据小于等于7字节，发送单帧数据
        TxData[0] = SINGLE_FRAME;  // 帧类型为单帧
        memcpy(&TxData[1], msg, len);
        g_canx_txheader.DLC = len + 1;  // 数据长度（包含帧类型）
        if (HAL_CAN_AddTxMessage(&g_canx_handler, &g_canx_txheader, TxData, &TxMailbox) != HAL_OK) /* 发送消息 */
        {
            return 1;
        }
    }
    else 
    {
        uint8_t offset = 0;
        uint8_t remaining_len = len;
        uint8_t frame_type = START_FRAME;
        
        while (remaining_len > 0) 
        {
            uint8_t current_frame_len = remaining_len > MAX_CAN_FRAME_SIZE - 1 ? MAX_CAN_FRAME_SIZE - 1 : remaining_len;  // 每帧最多8字节数据
            
            TxData[0] = frame_type;
            memcpy(&TxData[1], &msg[offset], current_frame_len);
            g_canx_txheader.DLC = current_frame_len + 1;
            if (HAL_CAN_AddTxMessage(&g_canx_handler, &g_canx_txheader, TxData, &TxMailbox) != HAL_OK) /* 发送消息 */
            {
                delay_us(100);
                return 1;
            }
            
            offset += current_frame_len;
            remaining_len -= current_frame_len;
            
            if (remaining_len > MAX_CAN_FRAME_SIZE - 1)
            {
                frame_type = DATA_FRAME;
            }
            else if (remaining_len > 0)
            {
                frame_type = END_FRAME;
            }
            
                   
            while (HAL_CAN_GetTxMailboxesFreeLevel(&g_canx_handler) != 3); /* 等待发送完成,所有邮箱(有三个邮箱)为空 */
            
        }
    }
//  if (HAL_CAN_AddTxMessage(&g_canx_handler, &g_canx_txheader, msg, &TxMailbox) != HAL_OK) /* 发送消息 */
//  {
//    return 1;
//  }
//  while (HAL_CAN_GetTxMailboxesFreeLevel(&g_canx_handler) != 3); /* 等待发送完成,所有邮箱为空 */
  return 0;
}

/**
 * @brief       CAN 接收数据查询
 *   @note      接收数据格式固定为: 标准ID, 数据帧
 * @param       id      : 要查询的 标准ID(11位)
 * @param       buf     : 数据缓存区
 * @retval      接收结果
 *   @arg       0   , 无数据被接收到;
 *   @arg       其他, 接收的数据长度
 */
uint8_t can_receive_msg(uint32_t id, uint8_t *buf)
{
  if (HAL_CAN_GetRxFifoFillLevel(&g_canx_handler, CAN_RX_FIFO0) == 0)     /* 没有接收到数据 */
  {
    return 0;
  }

  if (HAL_CAN_GetRxMessage(&g_canx_handler, CAN_RX_FIFO0, &g_canx_rxheader, buf) != HAL_OK)  /* 读取数据 */
  {
    return 0;
  }
  
  if (g_canx_rxheader.StdId!= id || g_canx_rxheader.IDE != CAN_ID_STD || g_canx_rxheader.RTR != CAN_RTR_DATA)       /* 接收到的ID不对 / 不是标准帧 / 不是数据帧 */
  {
    return 0;    
  }

  return g_canx_rxheader.DLC;

}


/**
 * @brief 发送网关状态广播
 * @param status_code 系统状态码
 */
void send_gateway_status(uint8_t status_code)
{
    uint8_t data[1];
    data[0] = status_code;
    // 直接调用底层的 can_send_msg, 它会处理单帧逻辑
    can_send_msg(CAN_ID_GATEWAY_STATUS, data, 1);
    delay_ms(20);
}


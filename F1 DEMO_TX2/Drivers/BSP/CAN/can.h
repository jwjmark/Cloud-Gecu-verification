/**
 ****************************************************************************************************
 * @file        can.h
 * @author      正点原子团队(ALIENTEK)
 * @version     V1.0
 * @date        2020-04-24
 * @brief       CAN 驱动代码
 * @license     Copyright (c) 2020-2032, 广州市星翼电子科技有限公司
 ****************************************************************************************************
 * @attention
 *
 * 实验平台:正点原子 STM32F103开发板
 * 在线视频:www.yuanzige.com
 * 技术论坛:www.openedv.com
 * 公司网址:www.alientek.com
 * 购买地址:openedv.taobao.com
 *
 * 修改说明
 * V1.0 20200424
 * 第一次发布
 *
 ****************************************************************************************************
 */

#ifndef __CAN_H
#define __CAN_H

#include "./SYSTEM/sys/sys.h"


/******************************************************************************************/
/* CAN 引脚 定义 */

#define CAN_RX_GPIO_PORT                GPIOA
#define CAN_RX_GPIO_PIN                 GPIO_PIN_11
#define CAN_RX_GPIO_CLK_ENABLE()        do{ __HAL_RCC_GPIOA_CLK_ENABLE(); }while(0)   /* PA口时钟使能 */

#define CAN_TX_GPIO_PORT                GPIOA
#define CAN_TX_GPIO_PIN                 GPIO_PIN_12
#define CAN_TX_GPIO_CLK_ENABLE()        do{ __HAL_RCC_GPIOA_CLK_ENABLE(); }while(0)   /* PA口时钟使能 */


#define MY_ECU_TARGET_ID    TARGET_ECU2
#define MY_ECU_KEY_ID       CAN_ID_KEY_DIST_ECU2
#define MY_ECU_ALERT_ID     CAN_ID_ECU2_ALERT

// ECU 运行状态机
typedef enum {
    STATE_WAIT_AUTH_DONE,   // 等待GECU广播“认证完成”

    STATE_SECURE_MODE,      // 密钥接收完成，进入安全通信模式
    STATE_ERROR             // 错误状态
} EcuState;

/******************************************************************************************/

/* CAN接收RX0中断使能 */
#define CAN_RX0_INT_ENABLE      0               /* 0,不使能; 1,使能; */

/* 函数声明 */
uint8_t can_receive_msg( uint8_t *buf);             /* CAN接收数据, 查询 */
uint8_t can_send_msg(uint32_t id, uint8_t *msg, uint8_t len);   /* CAN发送数据 */
uint8_t can_init(uint32_t tsjw,uint32_t tbs2,uint32_t tbs1,uint16_t brp,uint32_t mode); /* CAN初始化 */
char* ProcessData(uint8_t* data, uint16_t length);
void ecu_handle_can_receive(void);

#endif


















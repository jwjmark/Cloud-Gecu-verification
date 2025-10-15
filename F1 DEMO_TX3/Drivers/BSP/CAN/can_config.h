#ifndef __CAN_CONFIG_H
#define __CAN_CONFIG_H

/**
 * @brief CAN 总线消息ID定义
 * @note 根据 CAN_Signal_Definition.md 文档生成
 * @note 优先级原则: ID值越小，优先级越高
 */

// --- 最高优先级: 密钥分发 ---
#define CAN_ID_KEY_DIST_ECU1    0x101
#define CAN_ID_KEY_DIST_ECU2    0x102
#define CAN_ID_KEY_DIST_ECU3    0x103
#define CAN_ID_KEY_DIST_ECU4    0x104

// --- 高优先级: 攻击指令 ---
#define CAN_ID_ATTACK_CMD       0x200

// --- 中优先级: ECU错误警报 ---
#define CAN_ID_ECU1_ALERT       0x301
#define CAN_ID_ECU2_ALERT       0x302
#define CAN_ID_ECU3_ALERT       0x303
#define CAN_ID_ECU4_ALERT       0x304

// --- 低优先级: 网关状态广播 ---
#define CAN_ID_GATEWAY_STATUS   0x500

// --- 最低优先级: ECU常规通信 ---
#define CAN_ID_ECU_BASE 0x700 // 定义一个基础ID
#define CAN_ID_ECU1     0x701
#define CAN_ID_ECU2     0x702
#define CAN_ID_ECU3     0x703
#define CAN_ID_ECU4     0x704


/**
 * @brief 应用层信号定义
 */

// --- 网关状态广播 (ID: 0x500) ---
#define SYS_STATE_AUTH_DONE     0x10  // 认证完成，准备分发密钥
#define SYS_STATE_KEY_READY     0x20  // 密钥分发完成，可进行安全通信

// --- 攻击指令 (ID: 0x200) ---
// 目标ECU ID
#define TARGET_ECU1             0x01
#define TARGET_ECU2             0x02
#define TARGET_ECU3             0x03
#define TARGET_ECU4             0x04
// 攻击类型码
#define ATTACK_FUZZING          0xA1  // 模糊攻击
#define ATTACK_REPLAY           0xA2  // 重放攻击
#define ATTACK_FLOOD            0xA3  // 洪泛攻击
#define ATTACK_MASQUERADE       0xA4  // 伪装攻击

// --- ECU错误警报 (ID: 0x301 - 0x304) ---
#define ERROR_MSG_VALIDATION    0xE1  // 消息验证错误


// ========== 配置当前ECU的身份 ==========
// 将 MY_ECU_ID 设置为 1, 2, 3, 或 4
#define MY_ECU_ID                   3

// ========== 配置通信目标ECU ==========
// 将 TARGET_ECU_ID 设置为 1, 2, 3, 或 4 (不能是 MY_ECU_ID)
#define TARGET_ECU_ID               4
// ==========================================================


// 定义ECU之间通信的CAN ID基础地址
#define CAN_ID_ECU_MSG_BASE         0x200

// 根据上面的配置自动生成CAN ID
#define MY_ECU_RX_CAN_ID            (CAN_ID_ECU_MSG_BASE + MY_ECU_ID)
#define TARGET_ECU_CAN_ID           (CAN_ID_ECU_MSG_BASE + TARGET_ECU_ID)


#endif // __CAN_CONFIG_H

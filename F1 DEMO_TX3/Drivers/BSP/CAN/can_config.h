#ifndef __CAN_CONFIG_H
#define __CAN_CONFIG_H

/**
 * @brief CAN ������ϢID����
 * @note ���� CAN_Signal_Definition.md �ĵ�����
 * @note ���ȼ�ԭ��: IDֵԽС�����ȼ�Խ��
 */

// --- ������ȼ�: ��Կ�ַ� ---
#define CAN_ID_KEY_DIST_ECU1    0x101
#define CAN_ID_KEY_DIST_ECU2    0x102
#define CAN_ID_KEY_DIST_ECU3    0x103
#define CAN_ID_KEY_DIST_ECU4    0x104

// --- �����ȼ�: ����ָ�� ---
#define CAN_ID_ATTACK_CMD       0x200

// --- �����ȼ�: ECU���󾯱� ---
#define CAN_ID_ECU1_ALERT       0x301
#define CAN_ID_ECU2_ALERT       0x302
#define CAN_ID_ECU3_ALERT       0x303
#define CAN_ID_ECU4_ALERT       0x304

// --- �����ȼ�: ����״̬�㲥 ---
#define CAN_ID_GATEWAY_STATUS   0x500

// --- ������ȼ�: ECU����ͨ�� ---
#define CAN_ID_ECU_BASE 0x700 // ����һ������ID
#define CAN_ID_ECU1     0x701
#define CAN_ID_ECU2     0x702
#define CAN_ID_ECU3     0x703
#define CAN_ID_ECU4     0x704


/**
 * @brief Ӧ�ò��źŶ���
 */

// --- ����״̬�㲥 (ID: 0x500) ---
#define SYS_STATE_AUTH_DONE     0x10  // ��֤��ɣ�׼���ַ���Կ
#define SYS_STATE_KEY_READY     0x20  // ��Կ�ַ���ɣ��ɽ��а�ȫͨ��

// --- ����ָ�� (ID: 0x200) ---
// Ŀ��ECU ID
#define TARGET_ECU1             0x01
#define TARGET_ECU2             0x02
#define TARGET_ECU3             0x03
#define TARGET_ECU4             0x04
// ����������
#define ATTACK_FUZZING          0xA1  // ģ������
#define ATTACK_REPLAY           0xA2  // �طŹ���
#define ATTACK_FLOOD            0xA3  // �鷺����
#define ATTACK_MASQUERADE       0xA4  // αװ����

// --- ECU���󾯱� (ID: 0x301 - 0x304) ---
#define ERROR_MSG_VALIDATION    0xE1  // ��Ϣ��֤����


// ========== ���õ�ǰECU����� ==========
// �� MY_ECU_ID ����Ϊ 1, 2, 3, �� 4
#define MY_ECU_ID                   3

// ========== ����ͨ��Ŀ��ECU ==========
// �� TARGET_ECU_ID ����Ϊ 1, 2, 3, �� 4 (������ MY_ECU_ID)
#define TARGET_ECU_ID               4
// ==========================================================


// ����ECU֮��ͨ�ŵ�CAN ID������ַ
#define CAN_ID_ECU_MSG_BASE         0x200

// ��������������Զ�����CAN ID
#define MY_ECU_RX_CAN_ID            (CAN_ID_ECU_MSG_BASE + MY_ECU_ID)
#define TARGET_ECU_CAN_ID           (CAN_ID_ECU_MSG_BASE + TARGET_ECU_ID)


#endif // __CAN_CONFIG_H

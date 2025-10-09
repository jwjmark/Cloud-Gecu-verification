#include"./BYTE2STRING/byte2string.h"


//void StringToByte(char* source, uint8_t* dest, int sourceLen)
//{
//	int i;
//	uint8_t highByte, lowByte;

//	for (i = 0; i < sourceLen; i += 2)
//	{
//		highByte = toupper(source[i]);
//		lowByte  = toupper(source[i + 1]);

//		if (highByte > 0x39)
//			highByte -= 0x37;
//		else
//			highByte -= 0x30;

//		if (lowByte > 0x39)
//			lowByte -= 0x37;
//		else
//			lowByte -= 0x30;

//		dest[i / 2] = (highByte << 4) | lowByte;
//	}
//	return ;
//}

void ByteToString(const uint8_t* source, char* dest, int byteLen) {
    for (int i = 0; i < byteLen; i++) {
        // 将每个字节转换为两个十六进制字符
        sprintf(dest + (i * 2), "%02X", source[i]);
    }
    // 确保字符串以 null 结尾
    dest[byteLen * 2] = '\0';
}

// 辅助函数：将单个十六进制字符转换为整数值
int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 辅助函数：将十六进制字符串转换为字节数组
void hex_to_bytes(unsigned char* dest, const char* src, int byte_len) {
    for (int i = 0; i < byte_len; i++) {
        int high = hex_char_to_int(src[i * 2]);
        int low = hex_char_to_int(src[i * 2 + 1]);
        if (high != -1 && low != -1) {
            dest[i] = (high << 4) | low;
        } else {
            dest[i] = 0; // Handle error case
        }
    }
}

// 辅助函数：将字节数组转换为十六进制字符串
void bytes_to_hex(char* dest, const unsigned char* src, int byte_len) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(dest + i * 2, "%02x", src[i]);
    }
}
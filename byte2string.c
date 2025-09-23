#include"byte2string.h"


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

void ByteToString(const uint8_t* source, char* dest, int byteLen) {
    for (int i = 0; i < byteLen; i++) {
        // 将每个字节转换为两个十六进制字符
        sprintf(dest + (i * 2), "%02X", source[i]);
    }
    // 确保字符串以 null 结尾
    dest[byteLen * 2] = '\0';
}
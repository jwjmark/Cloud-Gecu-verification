#ifndef _ESP8266_H_
#define _ESP8266_H_

#include "./SYSTEM/sys/sys.h"




#define GID "gecu001"
#define PW "0123456789abcdef"
#define PQCG "fedcba9876543210"

extern char *out;
extern char PGID[65];
extern int esp_rxflag ;
extern int state ;      //开发板状态，0：身份认证状态；1：车内通信状态
extern char *QCG ;



//void uart2_receiver_handle(void);
uint8_t esp8266_config_network(void);
uint8_t esp8266_connect_server(void);
uint8_t esp8266_reset(void);
void uart3_receiver_clear(uint16_t len);
uint8_t esp8266_receive_msg(void);
uint8_t esp8266_send_msg(void);
void esp8266_init(void);
char* add_escape_characters(const char* json_str);

#endif


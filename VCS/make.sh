#! /bin/bash
gcc mqtt_client_ES.c cJSON.c sha256.c sm4.c  byte2string.c messageCheck.c -I./inc/pahomqtt/  -L./lib/ -I./   -lpaho-mqtt3c  -o mqtt_client_ES

#ifndef messageCheck_h
#define messageCheck_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "MQTTClient.h"
#include "cJSON.h"
#include"sha256.h"
#include"sm4.h"
#include"byte2string.h"


#define MSG_CHECK_OK 0
#define MSG_CHECK_ERROR_JSONTYPE 1
#define MSG_CHECK_ERROR_JSONKEY 2
#define MSG_CHECK_ERROR_DIGEST 3
#define MSG_CHECK_ERROR_TIMEVAL 4
#define MSG_CHECK_ERROR_KEY 5

void print_errorinfo(int errornum);
int check_json_keys(cJSON *json, const char *required_keys[], int num_required_keys);

int CheckMessage_ev2cs_auth (void * jsondata);

int CheckMessage1_gecu2vcs_auth (void * jsondata);

int CheckMessage2_gecu2vcs_auth (void * jsondata);

int CheckMessage3_gecu2vcs_auth (void * jsondata);

int CheckMessage_es2cs_auth (void * jsondata);

CJSON_PUBLIC(cJSON *) cJSON_Parse_ev2cs(const char *msg);











#endif
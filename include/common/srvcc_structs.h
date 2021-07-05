#ifndef __S11_STRUCTS_H_
#define __S11_STRUCTS_H_

#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <nas_structs.h>

#define S11_MSGBUF_SIZE 2048
#define DED_BEARER_COUNT 1"



typedef struct AdditionalMmContextForSrvcc
{
    Mobile_Station_Classmark_2 msclassmark2;
}AdditionalMmContextForSrvcc;
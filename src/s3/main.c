/*
 * Copyright 2019-present Open Networking Foundation
 * Copyright (c) 2019, Infosys Ltd.
 * Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "thread_pool.h"
#include "err_codes.h"
#include "ipc_api.h"
#include "s3.h"
#include "s3_config.h"
#include <sys/types.h>
#include "msgType.h"
#include "s3_options.h"
#include <gtpV2StackWrappers.h>
#include "gtp_cpp_wrapper.h"


/**Global and externs **/
extern s3_config_t g_s3_cfg;
/*s3 CP communication parameters*/
int g_s3_fd;
struct sockaddr_in g_s3_cp_addr;
socklen_t g_s3_serv_size;
struct sockaddr_in g_client_addr;
socklen_t g_client_addr_size;
int ipc_reader_tipc_s3;

int g_resp_fd;
pthread_t tipcReaders3_t;
pthread_mutex_t s3_net_lock = PTHREAD_MUTEX_INITIALIZER;

struct thread_pool *g_tpool;
struct thread_pool *g_tpool_tipc_reader_s3;

extern char processName[255];
uint32_t gtp_seq;
pthread_mutex_t seq_lock;

#define s3_IPC_MSG_BUF_LEN 4096

void handle_mmeapp_message_s3(void *data){

}
void * tipc_msg_handler_s3(){
    int bytesRead=0;
    unsigned char buffer[s3_IPC_MSG_BUF_LEN]={0};
    while(1){
        if((bytesRead=read_tipc_msg(ipc_reader_tipc_s3,buffer,s3_IPC_MSG_BUF_LEN))>0);{
        unsigned char *tmpBuf = (unsigned char *) malloc(sizeof(char) * bytesRead);
        memcpy(tmpBuf, buffer, bytesRead);
			log_msg(LOG_INFO, "s3 message received from mme-app, bytesRead %d", bytesRead);
            insert_job(g_tpool_tipc_reader_s3, handle_mmeapp_message_s3, tmpBuf);
    }
    bytesRead=0;
    }
}
struct GtpV2Stack* gtpStack_gp = NULL;
int
init_s3_workers()
{
	if ((ipc_reader_tipc_s3 = create_tipc_socket()) <= 0)
	{
		log_msg(LOG_ERROR, "Failed to create IPC Reader tipc socket ");
		return -E_FAIL;
	}
	if ( bind_tipc_socket(ipc_reader_tipc_s3, s3AppInstanceNum_c) != 1)
	{
		log_msg(LOG_ERROR, "Failed to bind IPC Reader tipc socket ");
		return -E_FAIL;
	}

	/* Initialize thread pool for mme-app messages */
	g_tpool_tipc_reader_s3 = thread_pool_new(3);

	if (g_tpool_tipc_reader_s3 == NULL) {
		log_msg(LOG_ERROR, "Error in creating thread pool. ");
		return -E_FAIL_INIT;
	}

	log_msg(LOG_INFO, "s3 Listener thead pool initalized.");

	// thread to read incoming ipc messages from tipc socket
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&tipcReaders3_t, &attr, &tipc_msg_handler_s3, NULL);
	pthread_attr_destroy(&attr);

	return 0;
}

int
init_gtpv2()
{
	/*Create UDP socket*/
	g_s3_fd = socket(PF_INET, SOCK_DGRAM, 0);

	g_client_addr.sin_family = AF_INET;
	//g_client_addr.sin_addr.s_addr = htonl(g_s3_cfg.local_egtp_ip);
	struct in_addr mme_local_addr = {g_s3_cfg.local_egtp_ip};
	fprintf(stderr, "....................local egtp %s", inet_ntoa(mme_local_addr));
	g_client_addr.sin_addr.s_addr = htonl(g_s3_cfg.local_egtp_ip);
	g_client_addr.sin_port = htons(g_s3_cfg.egtp_def_port);

	bind(g_s3_fd, (struct sockaddr *)&g_client_addr, sizeof(g_client_addr));
	g_client_addr_size = sizeof(g_client_addr);

	/*Configure settings in address struct*/
	g_s3_cp_addr.sin_family = AF_INET;
	//g_s11_cp_addr.sin_port = htons(g_s3_cfg.egtp_def_port);
	fprintf(stderr, ".................... egtp def port %d", g_s3_cfg.egtp_def_port);
	g_s3_cp_addr.sin_port = htons(g_s3_cfg.egtp_def_port);
	//g_s11_cp_addr.sin_addr.s_addr = htonl(g_s3_cfg.sgw_ip);
	struct in_addr sgsn_addr = {g_s3_cfg.target_ip};
	fprintf(stderr, "....................sgsn ip %s", inet_ntoa(sgsn_addr));
	g_s3_cp_addr.sin_addr.s_addr = g_s3_cfg.target_ip;
	memset(g_s3_cp_addr.sin_zero, '\0', sizeof(g_s3_cp_addr.sin_zero));

	g_s3_serv_size = sizeof(g_s3_cp_addr);

	return SUCCESS;
}
int
init_s3_ipc()
{
	log_msg(LOG_INFO, "Connecting to mme-app s3 CS response queue");
	if ((g_resp_fd  = create_tipc_socket()) <= 0)
		return -E_FAIL;

	log_msg(LOG_INFO, "S11 - mme-app IPC: Connected.");

	return 0;}


void
s3_reader()
{
	unsigned char buffer[s3_GTPV2C_BUF_LEN];
	int len;

	while(1) {
		//len = recvfrom(g_s3_fd, buffer, s3_GTPV2C_BUF_LEN, 0,
		//	&g_client_addr, &g_client_addr_size);
		len = recvfrom(g_s3_fd, buffer, s3_GTPV2C_BUF_LEN, 0,
			(struct sockaddr*)&g_s3_cp_addr, &g_s3_serv_size);

		if(len > 0) {
			MsgBuffer* tmp_buf_p = createMsgBuffer(len);
			uint32_t ip = ntohl(g_s3_cp_addr.sin_addr.s_addr);
			uint16_t src_port = ntohs(g_s3_cp_addr.sin_port);
			MsgBuffer_writeUint32(tmp_buf_p, ip, true);
			MsgBuffer_writeUint16(tmp_buf_p, src_port, true);
			MsgBuffer_writeBytes(tmp_buf_p, buffer, len, true);
			MsgBuffer_rewind(tmp_buf_p);
			log_msg(LOG_INFO, "s3 Received msg len : %d ",len);

			insert_job(g_tpool, handle_s3_message, tmp_buf_p);
		}

	}
}

void get_sequence(uint32_t *seq)
{
    pthread_mutex_lock(&seq_lock);
    gtp_seq = gtp_seq + 1;
    if(gtp_seq == 0xffffff) {
        gtp_seq = 0;
    }
    *seq = gtp_seq;
    pthread_mutex_unlock(&seq_lock);
    return;
} 
int main(int argc,char **argv){
    memcpy (processName, argv[0], strlen(argv[0]));
	
	init_backtrace(argv[0]);

	char *hp = getenv("MMERUNENV");
	if (hp && (strcmp(hp, "container") == 0)) {
		init_logging("container", NULL);
	}
	else { 
		init_logging("hostbased","/tmp/s3logs.txt" );
	}
    if (pthread_mutex_init(&seq_lock, NULL) != 0) {
        log_msg(LOG_ERROR,"mutex initialization failed");
    }
    init_cpp_gtp_tables();

	init_parser("conf/s3.json");
	parse_s3_conf();

	// init stack
	gtpStack_gp = createGtpV2Stack();
	if (gtpStack_gp == NULL)
	{
		log_msg(LOG_ERROR, "Error in initializing ipc.");
		return -1;
	}

	/*Init writer sockets*/
	if (init_s3_ipc() != 0) {
		log_msg(LOG_ERROR, "Error in initializing ipc.");
		return -1;
	}

	init_s3_workers();

	/* Initialize thread pool for S11 messages from CP*/
	g_tpool = thread_pool_new(s3_THREADPOOL_SIZE);

	if (g_tpool == NULL) {
		log_msg(LOG_ERROR, "Error in creating thread pool. ");
		return -1;
	}
	log_msg(LOG_INFO, "s3 listener threadpool initialized.");

	if (init_gtpv2() != 0)
		return -1;

	s3_reader();

	return 0;
}   

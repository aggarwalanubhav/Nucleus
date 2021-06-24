/*
 * Copyright 2019-present Open Networking Foundation
 * Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SV_CONFIG_H_
#define __SV_CONFIG_H_

#include <stdbool.h>

typedef struct sv_config
{
	unsigned int target_ip;
	unsigned int egtp_def_port;
	unsigned int local_egtp_ip;
} sv_config_t;

void
init_parser(char *path);

int
parse_sv_conf();

#endif /*__SV_CONFIG_H*/

/*
 * simple GPT parser
 * small memory footprint, dumb and simple implementation of GPT reading
 * for size contrainted bootloader
 *
 * Copyright (C) 2017 Samsung Electronics
 *
 * Ikjoon Jang <ij.jang@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef _XGPT_H_
#define _XGPT_H_

/* BE AWARE, Constraints of this code:
 *  - not tested fully
 *  - little endian CPU
 *  - GPT with protective MBR format
 *  - sector size is always 512bytes
 *  - only single buffer(sector sized) provided by caller is used.
 */

/* basic C definitions */
#include <stdint.h>

typedef enum {
	GPT_KEY_TYPE_PARTITION_GUID	= 0,
	GPT_KEY_TYPE_UNIQUE_GUID	= 1,
	GPT_KEY_TYPE_NAME_UTF16		= 2,
} xgpt_pe_key_t;

/* 128 bytes */
struct xgpt_entry {
	uint8_t	pguid[16];		/* partition type GUID */
	uint8_t	uguid[16];		/* uniqueue GUID */

	uint64_t	first_lba;
	uint64_t	last_lba;

	uint64_t	attr;
	uint16_t	name[36];
} __attribute__((packed));

/* caller should provide this as xgpt's lowlevel storage device I/O */
struct xgpt_storage_provider {
	uint8_t	*buffer;		/* 512 bytes, cpu's uint64_t accesible alignment */
	int (*open)(const int sector_size);
	int	(*read_sector)(struct xgpt_storage_provider *host, const int sector_nr);
	void (*close)(void);
};

int xgpt_init(struct xgpt_storage_provider *xgpt_host);
void xgpt_exit(void);

int xgpt_is_valid_entry(struct xgpt_entry *pe);

struct xgpt_entry* xgpt_find(xgpt_pe_key_t key_type, void *key);
struct xgpt_entry* xgpt_get(int part_nr);

#endif

/*
 * simple GPT parser
 * small memory footprint, dumb and simple implementation of GPT reading
 *
 * Copyright (C) 2017 Samsung Electronics
 *
 * Ikjoon Jang <ij.jang@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

/*
# GPT cheatsheet written in Markdown:

* https://en.wikipedia.org/wiki/Master_boot_record
* https://en.wikipedia.org/wiki/GUID_Partition_Table
* https://jbt.github.io/markdown-editor/
* PE: Partition Entry
* CHS: Cylinder-Head-Sector format

## Classic MBR
address | size | description
--------|------|----------------------
 0x000  | 446  | Bootstrap code area
 0x1BE  | 16   | PE 1
 0x1CE  | 16   | PE 2
 0x1DE  | 16   | PE 3
 0x1EE  | 16   | PE 4
 0x1FE  | 2    | Boot signature, 0xAA55

## MBR PE, @0x1be

16 bytes

 byte position | contents
---------------|-----------------------
 byte 0        | status
 byte 1-3      | first sector # in CHS
 byte 4        | partition type
 byte 5-7      | last sector # in CHS
 byte 8-11     | first sector # in LBA
 byte 12-15    | number of sectors

## GUID Partition Table

![GPT scheme](https://upload.wikimedia.org/wikipedia/commons/0/07/GUID_Partition_Table_Scheme.svg "gpt table scheme")

### GPT Header

512 bytes

 offset | len | contents
--------|-----|---------------
 0x00   |  8  | Signature ("EFI PART")
 0x08   |  4  | Revision (GPT version 1.0 = 00h 00h 01h 00h)
 0x0C   |  4  | Header size (usually  92)
 0x10   |  4  | CRC32/zlib of header
 0x14   |  4  | Reserved; must be zero
 0x18   |  8  | Current LBA
 0x20   |  8  | Backup LBA
 0x28   |  8  | First usable LBA
 0x30   |  8  | Last usable LBA
 0x38   |  16 | Disk GUID
 0x48   |  8  | Starting LBA of array of PEs (always 2 in primary copy)
 0x50   |  4  | Number of PEs in array
 0x54   |  4  | Size of a single PE (usually 80h or 128)
 0x58   |  4  | CRC32/zlib of partition array in little endian
 0x5C   |  *  | Reserved; must be zeroes for the rest of the block (usually 420 bytes)

### Partition entry

128 bytes

 offset | len | contents
--------|-----|---------------
 0x00   | 16  | Partition type GUID
 0x10   | 16  | Uniqeue partiiton GUID
 0x20   |  8  | First LBA
 0x28   |  8  | Last LBA
 0x30   |  8  | Attribute flags
 0x38   | 72  | Partition name (36 UTF-16LE)

#### Attribute flags
 Bit    | contents
--------|---------------
     0  | Platform required
     1  | EFI firmware should ignore the content of the partition and not try to read from it
     2  | Legacy BIOS bootable (equivalent to active flag of MBR partition)
  3-47  | Reserved for future use
 48-63  | Defined and used by the individual partition type

*/

#undef DEBUG
#define DEBUG

#ifdef DEBUG
# include <stdio.h>
# define print_err(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#else
# define print_err(fmt, ...)
#endif


#include <stddef.h>
#include "xgpt.h"

extern int memcmp(const void *s1, const void *s2, size_t n);

/* MBR header */
#define XGPTOFF_MBR_PE1				(0x1be)
#define XGPTOFF_MBR_SIG				(0x1fe)

/* MBR PE */
#define XGPTOFF_MBR_PE_PTYPE			(0x04)
#define XGPTOFF_MBR_PE_LBA			(0x08)
#define XGPTOFF_MBR_PE_NR			(0x0C)

#define XGPT_MBRPE_PTYPE_GPT_PROTECTIVE_MBR	(0xee)
#define XGOT_MBRPE_PTYPE_GPT_PROTECTIVE_EFI	(0xef)

/* GPT */
const char gpt_sig[8] = "EFI PART";

struct gpt_header {
	uint8_t	sig[8];

	uint32_t	revision;
	uint32_t	header_sz;

	uint32_t	crc32;
	uint32_t	reserved;

	uint64_t	current_lba;
	uint64_t	backup_lba;
	uint64_t	first_lba;
	uint64_t	last_lba;

	uint8_t	disk_guid[16];

	uint64_t	pes_lba;

	uint32_t	pes_nr;
	uint32_t	pe_sz;
	uint32_t	pes_crc32;
} __attribute__((packed));

struct xgpt {
	struct xgpt_storage_provider	*host;
	int				offset;		/* lba which host->buffer currently holds */
};

static struct xgpt xgpt;

static inline uint8_t read_byte(const uint8_t *buf, const int offset)
{
	return *(volatile uint8_t *)(&buf[offset]);
}

static inline uint16_t read_half(const uint8_t *buf, const int offset)
{
	const uintptr_t addr = (uintptr_t)&buf[offset];
	uint16_t ret;
	if (addr & 3)
		ret = (uint16_t)read_byte(buf, offset) | (uint16_t)(read_byte(buf, offset + 1) << 8);
	else
		ret = *(volatile uint16_t *)(&buf[offset]);
	return ret;
}

static inline uint32_t read_word(const uint8_t *buf, const int offset)
{
	const uintptr_t addr = (uintptr_t)&buf[offset];
	uint16_t ret;

	if (addr & 7)
		ret = (uint32_t)read_half(buf, offset) | (uint32_t)(read_half(buf, offset) << 16);
	else
		ret = *(volatile uint32_t *)(&buf[offset]);

	return ret;
}

static int read_sector(const int lba)
{
	if (!xgpt.host)
		return -1;

	if (xgpt.offset != lba)
		return xgpt.host->read_sector(xgpt.host, lba);
	else
		return 0;
}

static int xpgt_find_pguid(struct xgpt_entry *pe, void *key)
{
	return memcmp(pe->pguid, key, 16) == 0;
}
static int xpgt_find_uuid(struct xgpt_entry *pe, void *key)
{
	return memcmp(pe->uguid, key, 16) == 0;
}
static int xpgt_find_name(struct xgpt_entry *pe, void *key)
{
	return memcmp(pe->name, key, sizeof(pe->name)) == 0;
}

int xgpt_is_valid_entry(struct xgpt_entry *pe)
{
	uint32_t *ptr = (void*)pe->pguid;
	return  !!(ptr[0] || ptr[1] || ptr[2] || ptr[3]);
}

struct xgpt_entry* xgpt_find(xgpt_pe_key_t key_type, void *key)
{
	int lba;
	int (*find_func)(struct xgpt_entry *pe, void *key);

	switch (key_type) {
	case GPT_KEY_TYPE_PARTITION_GUID:
		find_func = xpgt_find_pguid;
		break;
	case GPT_KEY_TYPE_UNIQUE_GUID:
		find_func = xpgt_find_uuid;
		break;
	case GPT_KEY_TYPE_NAME_UTF16:
		find_func = xpgt_find_name;
		break;
	default:
		return NULL;
	}

	if (!xgpt.host)
		return NULL;

	for (lba = 2; lba < 34; lba++) {
		struct xgpt_entry *e;
		int i;

		if (read_sector(lba) < 0)
			return NULL;

		e = (void*)xgpt.host->buffer;
		for (i = 0; i < 4; i++) {
			if (!xgpt_is_valid_entry(e))
				return NULL;
			if (find_func(e, key))
				return e;
		}
	}
	return NULL;
}

struct xgpt_entry* xgpt_get(int part_nr)
{
	struct xgpt_storage_provider *host = xgpt.host;
	struct xgpt_entry *e;
	int ret;
	
	if (!host)
		return NULL;

	if (part_nr < 0 || part_nr > 127)
		return NULL;

	ret = read_sector(2 + (part_nr >> 2));
	if (ret < 0)
		return NULL;
	
	e = (void*)host->buffer;	
	return &e[part_nr & 3];
}

int xgpt_init(struct xgpt_storage_provider *host)
{
	struct gpt_header *header;
	const uint8_t *buf = host->buffer;
	int ret;
	uint16_t val16;
	uint32_t val32;
	
	if (!host->buffer || !host->read_sector)
		return -1;
	
	if (host->open) {
		ret = host->open(512);
		if (ret < 0)
			return ret;
	}

	/* LBA 0, MBR header */
	ret = host->read_sector(host, 0);
	if (ret < 0)
		return ret;

	/* basic checks on MBR and primary GPT */
	val16 = read_half(buf, 0x1fe);
	if (val16 != 0xaa55)
		return -2;

	/* MBR 1st primary partition: partition type & first LBA */
	if (read_byte(buf, XGPTOFF_MBR_PE1 + XGPTOFF_MBR_PE_PTYPE) != XGPT_MBRPE_PTYPE_GPT_PROTECTIVE_MBR)
		return -3;

	val32 = read_word(buf, XGPTOFF_MBR_PE1 + XGPTOFF_MBR_PE_LBA);
	if (val32 != 1)
		return -4;

	/* LBA 1, primary GPT header */
	ret = host->read_sector(host, 1);
	if (ret < 0)
		return ret;

	header = (void*)buf;

	if (header->current_lba != 1)
		return -5;

	if (header->pes_lba != 2)
		return -6;

	if (header->pe_sz != 128)
		return -7;

	if (header->pes_nr != 128)
		return -8;

	xgpt.host = host;
	xgpt.offset = 1;

	return 0;
}

void xgpt_exit(void)
{
	struct xgpt_storage_provider *host = xgpt.host;
	if (host) {
		if (host->close)
			host->close();
	}
	xgpt.host = NULL;
}
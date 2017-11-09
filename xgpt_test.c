/* XGPT test driver */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include "xgpt.h"

static char *file_path;
static int given_sector_size;
static int fd;

struct xgpt_storage_provider host;

static int _file_open(const int sector_size)
{
	printf ("open %s\n", file_path);
	fd = open(file_path, O_RDONLY);
	if (fd < 0) {
		return fd;
	}
	given_sector_size = sector_size;
	return 0;
}

static void _file_close(void)
{
	close(fd);
	fd = -1;
}

static int _read_sector(struct xgpt_storage_provider *host, const int lba)
{
	int ret;
	lseek(fd, lba * given_sector_size, SEEK_SET);
	//printf ("read sector %d\n", lba);
	ret = read(fd, host->buffer, 512);
	if (ret != 512)
		return -1;
	else
		return 0;
}

static void utf16_to_ascii_danger(uint8_t *dst, uint16_t *src, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		dst[i] = src[i];
		if (!dst[i])
			break;
	}
		
}

static void dump_entry(const int part, struct xgpt_entry *e)
{
	char name[40] = {0, };
	utf16_to_ascii_danger(name, e->name, 36);
	printf("partition %d: %10lu %10lu %s\n", part, e->first_lba, e->last_lba, name);
}

static uint8_t buffer[512];

int main(int argc, char *argv[])
{
	int i, ret;
	
	file_path = argv[1];
	
	host.buffer = buffer;
	host.open = _file_open;
	host.close = _file_close;
	host.read_sector = _read_sector;
	
	ret = xgpt_init(&host);
	if (ret < 0) {
		fprintf(stderr, "init failed %d\n", ret);
		return -1;
	}
	
	for (i = 0; i < 128; i++) {
		struct xgpt_entry *e = xgpt_get(i);
		if (!e) {
			printf ("getting entry%d fail\n", i);
			break;
		}
		
		if (xgpt_is_valid_entry(e)) {
			dump_entry(i, e);
		} else {
			break;
		}
	}
	
	xgpt_exit();
}

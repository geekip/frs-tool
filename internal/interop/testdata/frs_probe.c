#include "frs/domain.h"
#include "frs/frs.h"
#include "frs/ip.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **out, size_t *length)
{
  FILE *file;
  long size;
  uint8_t *data;
  if (path == NULL || out == NULL || length == NULL) return 0;
  file = fopen(path, "rb");
  if (file == NULL) return 0;
  if (fseek(file, 0, SEEK_END) != 0) {
    (void)fclose(file);
    return 0;
  }
  size = ftell(file);
  if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
    (void)fclose(file);
    return 0;
  }
  data = (uint8_t *)malloc((size_t)size);
  if (data == NULL || fread(data, 1u, (size_t)size, file) != (size_t)size) {
    free(data);
    (void)fclose(file);
    return 0;
  }
  if (fclose(file) != 0) {
    free(data);
    return 0;
  }
  *out = data;
  *length = (size_t)size;
  return 1;
}

static ftun_string_t text(const char *value)
{
  ftun_string_t result;
  result.data = value;
  result.length = strlen(value);
  return result;
}

int main(int argc, char **argv)
{
  uint8_t *data = NULL;
  size_t length = 0u;
  ftun_frs_view_t *view = NULL;
  ftun_frs_set_t *set = NULL;
  ftun_frs_set_kind_t kind;
  bool matched = false;
  bool expected;
  ftun_status_t status;
  int result = 1;
  if (argc != 6 || !read_file(argv[1], &data, &length)) {
    fprintf(stderr, "usage: frs-probe FILE KIND LABEL VALUE EXPECTED\n");
    goto done;
  }
  if (strcmp(argv[2], "ip") == 0) kind = FTUN_FRS_SET_IP;
  else if (strcmp(argv[2], "domain") == 0) kind = FTUN_FRS_SET_DOMAIN;
  else {
    fprintf(stderr, "unsupported query kind\n");
    goto done;
  }
  expected = strcmp(argv[5], "1") == 0;
  status = ftun_frs_open_bytes((ftun_bytes_t){data, length}, &view);
  if (status != FTUN_OK) {
    fprintf(stderr, "real C loader rejected Go output: %d\n", (int)status);
    goto done;
  }
  status = ftun_frs_bind(view, kind, text(argv[3]), &set);
  if (status != FTUN_OK) {
    fprintf(stderr, "real C loader could not bind set: %d\n", (int)status);
    goto done;
  }
  if (kind == FTUN_FRS_SET_IP) {
    uint8_t address[4];
    if (inet_pton(AF_INET, argv[4], address) != 1) {
      fprintf(stderr, "invalid IPv4 query\n");
      goto done;
    }
    status = ftun_frs_ip_contains(set, address, &matched);
  } else {
    status = ftun_frs_domain_contains(set, text(argv[4]), &matched);
  }
  if (status != FTUN_OK || matched != expected) {
    fprintf(stderr, "query mismatch: status=%d actual=%d expected=%d\n",
            (int)status, matched ? 1 : 0, expected ? 1 : 0);
    goto done;
  }
  result = 0;

done:
  if (set != NULL && ftun_frs_set_release(&set) != FTUN_OK) result = 1;
  if (view != NULL && ftun_frs_view_release(&view) != FTUN_OK) result = 1;
  free(data);
  return result;
}

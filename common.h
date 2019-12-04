/*
 * Copyright (c) 2016 · Trung Huynh
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "json/jsmn.h"

#include "clouduploader.h"

int date_validate(char *date);
void init_string(string_t *s);
size_t writefunc(void *ptr, size_t size, size_t nmemb, string_t *s);
size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream);
void json_get_str(jsmntok_t *t, const char *data, char *name);
void json_get_int(jsmntok_t *t, const char *data, int *number);

#endif /* COMMON_H_ */
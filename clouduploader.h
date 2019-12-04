/*
 * Copyright (c) 2016 · Trung Huynh
 */
 
#ifndef __CLOUDUPLOADER_H__
#define __CLOUDUPLOADER_H__

#include <stdint.h>

#define MAXBUF      1024
#define MAX_EVENT   3

typedef struct string {
    char *ptr;
    size_t len;
}string_t;

typedef struct params
{
    char *filepath;
    char *create_dir;
    char *root_dir;
    char *conf_file;
    uint8_t is_reauth;
    
    uint8_t key[32];
    char buff[MAXBUF * 4];
    
    int (*config_encryption)(const char *, const uint8_t *, char *);
}params_t;

#endif // __CLOUDUPLOADER_H__

/*
 * Copyright (c) 2016 · Trung Huynh
 */
 
#ifndef __GDRIVEUPLOADER_H__
#define __GDRIVEUPLOADER_H__

#include "clouduploader.h"

#define GOOGLE_SECTION          "google_drive"
#define GOOGLE_CLIENT_ID        "client_id"
#define GOOGLE_CLIENT_SECRET    "client_secret"
#define GOOGLE_REFRESH_TOKEN    "refresh_token"
#define GOOGLE_ACCESS_TOKEN     "access_token"
#define GOOGLE_ROOT_FOLDER      "root_folder"
#define GOOGLE_CREATED_TIME     "created_time"
#define GOOGLE_EXPIRED_IN       "expired_in"

typedef struct google_config
{
   char client_id[MAXBUF];
   char client_secret[MAXBUF];
   char refresh_token[MAXBUF];
   char access_token[MAXBUF];
   unsigned int created_time;
   int expired_in;
   char root_folder[MAXBUF];
}google_config_t;

int gdrive(Config *, params_t *, uint8_t);

#endif // __GDRIVEUPLOADER_H__

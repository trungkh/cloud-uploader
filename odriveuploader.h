/*
 * Copyright (c) 2016 · Trung Huynh
 */

#ifndef ODRIVEUPLOADER_H_
#define ODRIVEUPLOADER_H_

#include "clouduploader.h"

#define ONEDRIVE_SECTION        "one_drive"
#define ONEDRIVE_CLIENT_ID      "client_id"
#define ONEDRIVE_CLIENT_SECRET  "client_secret"
#define ONEDRIVE_REFRESH_TOKEN  "refresh_token"
#define ONEDRIVE_ACCESS_TOKEN   "access_token"
#define ONEDRIVE_ROOT_FOLDER    "root_folder"
#define ONEDRIVE_CREATED_TIME   "created_time"
#define ONEDRIVE_EXPIRED_IN     "expired_in"

typedef struct onedrive_config
{
   char client_id[MAXBUF];
   char client_secret[MAXBUF];
   char refresh_token[MAXBUF];
   char access_token[MAXBUF*2];
   unsigned int created_time;
   int expired_in;
   char root_folder[MAXBUF];
}onedrive_config_t;

int odrive(Config *, params_t *, uint8_t);

#endif /* ODRIVEUPLOADER_H_ */

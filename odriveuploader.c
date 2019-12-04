/*
 * Copyright (c) 2016 · Trung Huynh
 */

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>

#include "configini/configini.h"
#include "crypto/encrypt.h"
#include "crypto/decrypt.h"
#include "json/jsmn.h"

#include "clouduploader.h"
#include "odriveuploader.h"
#include "common.h"

#define MAX_SIMPLE_UPLOAD_SIZE  104857600
#define MAX_CHUNK_SIZE          10158080

static unsigned char debug = 0;

static int get_refresh_token(const char *client_id, const char *client_secret, const char *code,
        char *refresh_token, char *access_token, int *expired_in)
{
    CURL *curl;
    char getRefreshToken[] = "https://login.live.com/oauth20_token.srf";
    char error_str[128];

    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char content[512] = {'\0'};
        string_t response;
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[16]; /* We expect no more than 128 tokens */

        init_string(&response);

        sprintf(content, "client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=https://login.live.com/oauth20_desktop.srf",
                client_id, client_secret, code);

        chunk = curl_slist_append(chunk, "Host: login.live.com");
        chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
        //chunk = curl_slist_append(chunk, "Cache-Control: no-cache");

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, getRefreshToken);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "get_refresh_token failed: %s\n", curl_easy_strerror(res));
            return res;
        }

        jsmn_init(&p);
        ret = jsmn_parse(&p, response.ptr, strlen(response.ptr), t, sizeof(t) / sizeof(t[0]));
        if(ret < 0)
        {
            printf("Failed to parse JSON: %d\n", ret);
            ret = 1;
        }
        else if(ret < 1 || t[0].type != JSMN_OBJECT)
        {
            printf("Object expected\n");
            ret = 1;
        }
        else
        {
            for (i = 0; i < ret; i++)
            {
                if(t[i].type == JSMN_STRING && t[i].size == 1) // must be key
                {
                    json_get_str(&t[i], response.ptr, name);
                    if (!strcmp(name, ONEDRIVE_ACCESS_TOKEN))
                    {
                        json_get_str(&t[++i], response.ptr, access_token);
                    }
                    else if (!strcmp(name, ONEDRIVE_REFRESH_TOKEN))
                    {
                        json_get_str(&t[++i], response.ptr, refresh_token);
                    }
                    else if (!strcmp(name, "expires_in"))
                    {
                        json_get_int(&t[++i], response.ptr, expired_in);
                    }
                    else if (!strcmp(name, "error"))
                    {
                        json_get_str(&t[++i], response.ptr, error_str);
                        printf("Error: %s", error_str);
                    }
                }
            }
            ret = 0;
        }

        free(response.ptr);
        return ret;
    }
    return 1;
}

static int get_access_token(const char *client_id, const char *client_secret,
        char *refresh_token, char *access_token, int *expired_time)
{
    CURL *curl;
    char getAccessToken[] = "https://login.live.com/oauth20_token.srf";
    char error_str[64];

    curl = curl_easy_init();
    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char content[512] = {'\0'};
        char content_len[32] = {'\0'};
        string_t response;
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[16]; /* We expect no more than 128 tokens */

        init_string(&response);

        sprintf(content, "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token",
                client_id, client_secret, refresh_token);
        sprintf(content_len, "Content-Length: %ld", strlen(content));

        chunk = curl_slist_append(chunk, "Host: login.live.com");
        chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
        chunk = curl_slist_append(chunk, content_len);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, getAccessToken);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "get_access_token failed: %s\n", curl_easy_strerror(res));
            return res;
        }

        jsmn_init(&p);
        ret = jsmn_parse(&p, response.ptr, strlen(response.ptr), t, sizeof(t) / sizeof(t[0]));
        if(ret < 0)
        {
            printf("Failed to parse JSON: %d\n", ret);
            ret = 1;
        }
        else if(ret < 1 || t[0].type != JSMN_OBJECT)
        {
            printf("Object expected\n");
            ret = 1;
        }
        else
        {
            for (i = 0 ; i < ret ; i++)
            {
                if(t[i].type == JSMN_STRING && t[i].size == 1 ) // must be key
                {
                    json_get_str(&t[i], response.ptr, name);
                    if (!strcmp(name,ONEDRIVE_ACCESS_TOKEN))
                    {
                        json_get_str(&t[++i], response.ptr, access_token);
                    }
                    else if (!strcmp(name,ONEDRIVE_REFRESH_TOKEN))
                    {
                        json_get_str(&t[++i], response.ptr, refresh_token);
                    }
                    else if (!strcmp(name,"expires_in"))
                    {
                        json_get_int(&t[++i], response.ptr, expired_time);
                    }
                    /*else if (!strcmp(name,"user_id"))
                    {
                        json_get_str(&t[++i], response.ptr, NULL);
                    }*/
                    else if (!strcmp(name, "error"))
                    {
                        json_get_str(&t[++i], response.ptr, error_str);
                        printf("Error: %s", error_str);
                    }
                }
            }
            ret = 0;
        }
        free(response.ptr);
        return ret;
    }
    return 1;
}

static int get_folder_id(const char *access_token, const char *folderid,
        const char *foldername, char *folderid_res)
{
    CURL *curl;

    curl = curl_easy_init();

    if(curl)
    {
        char link[2048] = {'\0'};
        string_t response;
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[80]; /* We expect no more than 128 tokens */

        char *output = curl_easy_escape(curl, foldername, strlen(foldername));
        init_string(&response);

        if (!strcmp(folderid, "root"))
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/%s:/%s?access_token=%s",
                    folderid, output, access_token);
        }
        else
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/items/%s:/%s?access_token=%s",
                    folderid, output, access_token);
        }
        curl_free(output);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, link);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "get_folder_id failed: %s\n", curl_easy_strerror(res));
            return res;
        }

        jsmn_init(&p);
        ret = jsmn_parse(&p, response.ptr, strlen(response.ptr), t, sizeof(t) / sizeof(t[0]));
        if(ret < 0)
        {
            printf("Failed to parse JSON: %d\n", ret);
            ret = 1;
        }
        else if(ret < 1 || t[0].type != JSMN_OBJECT)
        {
            printf("Object expected\n");
            ret = 1;
        }
        else
        {
            ret = -1;
            for (i = 0 ; i < ret ; i++)
            {
                if(t[i].type == JSMN_STRING && t[i].size == 1) // must be key
                {
                    json_get_str(&t[i], response.ptr, name);
                    if (!strcmp(name, "eTag"))
                    {
                        i += 2;
                        if(t[i].type == JSMN_STRING && t[i].size == 1)
                        {
                            json_get_str(&t[i], response.ptr, name);
                            if (!strcmp(name, "id"))
                            {
                                json_get_str(&t[i + 1], response.ptr, folderid_res);
                                ret = 0;
                                break;
                            }
                        }
                    }
                }
            }
        }
        free(response.ptr);
        return ret;
    }
    return 1;
}

static int create_folder_id(const char *access_token, const char *folderid,
        const char *foldername, char *folderid_res)
{
    CURL *curl;

    curl = curl_easy_init();
    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char content[256] = {'\0'};
        char content_len[32] = {'\0'};
        char link[2048] = {'\0'};
        string_t response;
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[80]; /* We expect no more than 128 tokens */

        init_string(&response);

        sprintf(content, "{\"name\":\"%s\",\"folder\":{},\"@name.conflictBehavior\":\"fail\"}",
                foldername);
        sprintf(content_len, "Content-Length: %ld", strlen(content));
        if (!strcmp(folderid, "root"))
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/%s/children?access_token=%s",
                    folderid, access_token);
        }
        else
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/items/%s/children?access_token=%s",
                    folderid, access_token);
        }

        chunk = curl_slist_append(chunk, "Host: api.onedrive.com");
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        chunk = curl_slist_append(chunk, content_len);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, link);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "create_folder_id failed: %s\n", curl_easy_strerror(res));
            return res;
        }

        jsmn_init(&p);
        ret = jsmn_parse(&p, response.ptr, strlen(response.ptr), t, sizeof(t) / sizeof(t[0]));
        if(ret < 0)
        {
            printf("Failed to parse JSON: %d\n", ret);
            ret = 1;
        }
        else if(ret < 1 || t[0].type != JSMN_OBJECT)
        {
            printf("Object expected\n");
            ret = 1;
        }
        else
        {
            for (i = 0 ; i < ret ; i++)
            {
                if(t[i].type == JSMN_STRING && t[i].size == 1) // must be key
                {
                    json_get_str(&t[i], response.ptr, name);
                    if (!strcmp(name, "eTag"))
                    {
                        i += 2;
                        if(t[i].type == JSMN_STRING && t[i].size == 1)
                        {
                            json_get_str(&t[i], response.ptr, name);
                            if (!strcmp(name, "id"))
                            {
                                json_get_str(&t[i + 1], response.ptr, folderid_res);
                                ret = 0;
                                break;
                            }
                        }
                    }
                }
            }
        }
        free(response.ptr);
        return ret;
    }
    return 1;
}

static int request_upload_session(const char *access_token, char *file_path,
        const char *folderid, char *upload_link)
{
    CURL *curl;

    curl = curl_easy_init();
    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char content[256] = {'\0'};
        char content_len[32] = {'\0'};
        char link[2048] = {'\0'};
        char *file_name = NULL;
        string_t response;
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[16]; /* We expect no more than 128 tokens */

        file_name = strrchr(file_path, '/');
        if (file_name == NULL)
        {
            file_name = file_path;
        }
        else
        {
            file_name++;
        }

        init_string(&response);

        sprintf(content, "{\"item\":{\"@name.conflictBehavior\":\"replace\",\"name\":\"%s\"}}",
                file_name);
        sprintf(content_len, "Content-Length: %ld", strlen(content));

        file_name = curl_easy_escape(curl, file_name, strlen(file_name));
        if (!strcmp(folderid, "root"))
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/%s:/%s:/upload.createSession?access_token=%s",
                    folderid, file_name, access_token);
        }
        else
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/items/%s:/%s:/upload.createSession?access_token=%s",
                    folderid, file_name, access_token);
        }
        free(file_name);

        chunk = curl_slist_append(chunk, "Host: api.onedrive.com");
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        chunk = curl_slist_append(chunk, content_len);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, link);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "request_upload_session failed: %s\n", curl_easy_strerror(res));
            return res;
        }

        jsmn_init(&p);
        ret = jsmn_parse(&p, response.ptr, strlen(response.ptr), t, sizeof(t) / sizeof(t[0]));
        if(ret < 0)
        {
            printf("Failed to parse JSON: %d\n", ret);
            ret = 1;
        }
        else if(ret < 1 || t[0].type != JSMN_OBJECT)
        {
            printf("Object expected\n");
            ret = 1;
        }
        else
        {
            ret = 1;
            for (i = 0 ; i < ret ; i++)
            {
                if(t[i].type == JSMN_STRING && t[i].size == 1) // must be key
                {
                    json_get_str(&t[i], response.ptr, name);
                    if (!strcmp(name,"uploadUrl"))
                    {
                        json_get_str(&t[++i], response.ptr, upload_link);
                        ret = 0;
                        break;
                    }
                }
            }
        }
        free(response.ptr);
        return ret;
    }

    return 1;
}

static int upload_file_chunked(const char *access_token, char *file_path, const char *folder_id)
{
    char link_upload[2048] = {'\0'};
    if (!request_upload_session(access_token, file_path, folder_id, link_upload))
    {
        //Here we go
    }
    return 1;
}

static int upload_file_simple(const char *access_token, char *file_path,
        const char *folderid, curl_off_t file_size)
{
    CURL *curl;

    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "open file %s failed\n", file_path);
        return 1;
    }
    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char link[2048] = {'\0'};
        char *file_name = NULL;
        CURLcode res;

        file_name = strrchr(file_path, '/');
        if (file_name == NULL)
        {
            file_name = file_path;
        }
        else
        {
            file_name++;
        }

        file_name = curl_easy_escape(curl, file_name, strlen(file_name));
        if (!strcmp(folderid, "root"))
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/%s/children/%s/content?access_token=%s",
                    folderid, file_name, access_token);
        }
        else
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/items/%s/children/%s/content?access_token=%s",
                    folderid, file_name, access_token);
        }
        free(file_name);

        chunk = curl_slist_append(chunk, "Host: api.onedrive.com");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_PUT, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, fp);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, file_size);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, link);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
        {
            fprintf(stderr, "upload_file failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        return res;
    }
    return 1;
}

static char *get_file_list(const char *access_token, const char *folder_id)
{
    CURL *curl;

    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char link[2048] = {'\0'};
        string_t response;
        CURLcode res;

        init_string(&response);

        if (!strcmp(folder_id, "root"))
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/%s/children?"
                    "select=name,id,createdDateTime&orderby=createdDateTime%%20desc&access_token=%s",
                    folder_id, access_token);
        }
        else
        {
            sprintf(link, "https://api.onedrive.com/v1.0/drive/items/%s/children?"
                    "select=name,id,createdDateTime&orderby=createdDateTime%%20desc&access_token=%s",
                    folder_id, access_token);
        }

        chunk = curl_slist_append(chunk, "Host: api.onedrive.com");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, link);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "get_file_list failed: %s\n", curl_easy_strerror(res));
            return NULL;
        }

        return response.ptr;
    }
    return NULL;
}

static int delete_file(const char *access_token, const char *file_id)
{
    CURL *curl;

    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char link[2048] = {'\0'};
        CURLcode res;

        sprintf(link, "https://api.onedrive.com/v1.0/drive/items/%s?access_token=%s",
                file_id, access_token);

        chunk = curl_slist_append(chunk, "Host: api.onedrive.com");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, link);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
        {
            fprintf(stderr, "delete_file failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        return res;
    }
    return 1;
}

static int del_old_files(const char *access_token, const char *json_str)
{
    int ret, i;
    jsmn_parser p;
    char key[32] = {'\0'};
    char val[256] = {'\0'};
    jsmntok_t *t;

    int count = 0;
    const char *tmp = json_str;
    while(NULL != (tmp = strstr(tmp, "name")))
    {
       count++;
       tmp++;
    }

    t = (jsmntok_t *)malloc(sizeof(jsmntok_t) * ((count - 1) * 7 + 5));
    jsmn_init(&p);
    ret = jsmn_parse(&p, json_str, strlen(json_str), t, (count - 1) * 7 + 5);
    if(ret < 0)
    {
        printf("Failed to parse JSON: %d\n", ret);
        ret = 1;
    }
    else if(ret < 1 || t[0].type != JSMN_OBJECT)
    {
        printf("Object expected\n");
        ret = 1;
    }
    else
    {
        char date[9] = {'\0'};
        char store[256] = {'\0'};
        count = 0;

        for (i = 0; i < ret; i++)
        {
            if(t[i].type == JSMN_STRING && t[i].size == 1) // must be key
            {
                json_get_str(&t[i], json_str, key);
                if (!strcmp(key, "name"))
                {
                    json_get_str(&t[++i], json_str, val);
                    if (strlen(val) > 33)
                    {
                        strncpy(date, val + 16, 8);
                        if (!date_validate(date) && strncmp(store, val, 33))
                        {
                            count++;
                            if (count == (MAX_EVENT + 1))
                                break;
                            strcpy(store, val);
                            store[strlen(val)] = '\0';
                        }
                    }
                }
                else if (!strcmp(key, "value"))
                {
                    if (t[i + 1].type == JSMN_ARRAY && t[i + 1].size > 0)
                        i++;
                }
            }
        }

        if (count == (MAX_EVENT + 1))
        {
            for (i = i - ((i - 5) % 7); i < ret; i++)
            {
                if(t[i].type == JSMN_STRING && t[i].size == 1 ) // must be key
                {
                    json_get_str(&t[i], json_str, key);
                    if (!strcmp(key, "name"))
                    {
                        json_get_str(&t[++i], json_str, val);
                        if (strlen(val) > 33)
                        {
                            strncpy(date, val + 16, 8);
                            if (!date_validate(date))
                            {
                                json_get_str(&t[++i], json_str, key);
                                if (!strcmp(key, "id"))
                                {
                                    json_get_str(&t[++i], json_str, val);
                                    delete_file(access_token, val);
                                }
                            }
                        }
                    }
                }
            }
        }
        ret = 0;
    }
    free(t);
    return ret;
}

int odrive(Config *cfg, params_t *param, uint8_t d)
{
    onedrive_config_t config;
    char folder_id[32] = {'\0'};
    char user_code[64] = {'\0'};

    time_t now = time(0);
    debug = d;

    ConfigReadString(cfg, ONEDRIVE_SECTION, ONEDRIVE_CLIENT_ID, config.client_id, sizeof(config.client_id), "");
    ConfigReadString(cfg, ONEDRIVE_SECTION, ONEDRIVE_REFRESH_TOKEN, config.refresh_token, sizeof(config.refresh_token), "");
    ConfigReadString(cfg, ONEDRIVE_SECTION, ONEDRIVE_ACCESS_TOKEN, config.access_token, sizeof(config.access_token), "");
    ConfigReadString(cfg, ONEDRIVE_SECTION, ONEDRIVE_ROOT_FOLDER, config.root_folder, sizeof(config.root_folder), "root");
    ConfigReadUnsignedInt(cfg, ONEDRIVE_SECTION, ONEDRIVE_CREATED_TIME, &config.created_time, 0);
    ConfigReadInt(cfg, ONEDRIVE_SECTION, ONEDRIVE_EXPIRED_IN, &config.expired_in, 0);

    //We don't use client_secret in any transactions
    memset(config.client_secret, '\0', sizeof(config.client_secret));

    if (param->root_dir == NULL)
    {
        param->root_dir = config.root_folder;
    }
    else
    {
        ConfigAddString(cfg, ONEDRIVE_SECTION, ONEDRIVE_ROOT_FOLDER, param->root_dir);
        ConfigPrintToBuffer(cfg, param->buff);
        param->config_encryption(param->conf_file, param->key, param->buff);
    }

    if (!strlen(config.refresh_token) || param->is_reauth)
    {
        printf("Please open the following URL in your browser and follow the steps until you see a blank page:");
        printf("https://login.live.com/oauth20_authorize.srf?client_id=%s&scope=wl.offline_access%%20onedrive.readwrite"
                "&response_type=code&redirect_uri=https://login.live.com/oauth20_desktop.srf", config.client_id);
        printf("\nWhen ready, please enter the value of the code parameter (from the URL of the blank page) and press enter\n");
        printf("Code: ");
        scanf("%s", user_code);

        if (!get_refresh_token(config.client_id, config.client_secret, user_code, config.refresh_token,
                config.access_token, &config.expired_in))
        {
            if (!strlen(config.refresh_token))
            {
                printf("Cannot get refresh token\n");
                return -1;
            }

            config.created_time = now;
            ConfigAddString(cfg, ONEDRIVE_SECTION, ONEDRIVE_REFRESH_TOKEN, config.refresh_token);
            ConfigAddString(cfg, ONEDRIVE_SECTION, ONEDRIVE_ACCESS_TOKEN, config.access_token);
            ConfigAddUnsignedInt(cfg, ONEDRIVE_SECTION, ONEDRIVE_CREATED_TIME, config.created_time);
            ConfigAddInt(cfg, ONEDRIVE_SECTION, ONEDRIVE_EXPIRED_IN, config.expired_in);
            ConfigPrintToBuffer(cfg, param->buff);
            param->config_encryption(param->conf_file, param->key, param->buff);
            memset(param->buff, 0, sizeof(param->buff));

            if (param->is_reauth) return 0;
        }
        else
        {
            printf("Get refresh token failed\n");
            return -1;
        }
    }
    if (!strlen(config.access_token) || config.created_time == 0 || config.expired_in == 0 ||
            (now - config.created_time) > (config.expired_in - 120))
    {
        config.access_token[0] = '\0';
        if (get_access_token(config.client_id, config.client_secret, config.refresh_token,
                config.access_token, &config.expired_in) || !strlen(config.access_token))
        {
            printf("Cannot get access token\n");
            return 1;
        }
        config.created_time = now;
        ConfigAddString(cfg, ONEDRIVE_SECTION, ONEDRIVE_REFRESH_TOKEN, config.refresh_token);
        ConfigAddString(cfg, ONEDRIVE_SECTION, ONEDRIVE_ACCESS_TOKEN, config.access_token);
        ConfigAddUnsignedInt(cfg, ONEDRIVE_SECTION, ONEDRIVE_CREATED_TIME, config.created_time);
        ConfigAddInt(cfg, ONEDRIVE_SECTION, ONEDRIVE_EXPIRED_IN, config.expired_in);
        ConfigPrintToBuffer(cfg, param->buff);
        param->config_encryption(param->conf_file, param->key, param->buff);
        memset(param->buff, 0, sizeof(param->buff));
    }
    if (param->create_dir != NULL && strlen(config.access_token) > 0 && config.created_time > 0 &&
            config.expired_in > 0 && (now - config.created_time) < (config.expired_in - 120))
    {
        if (0 >= get_folder_id(config.access_token, "root", param->create_dir, folder_id))
        {
            if (strlen(folder_id) > 0)
            {
                printf("Folder '%s' have already existed in root\n", param->create_dir);
                ConfigAddString(cfg, ONEDRIVE_SECTION, ONEDRIVE_ROOT_FOLDER, folder_id);
                ConfigPrintToBuffer(cfg, param->buff);
                param->config_encryption(param->conf_file, param->key, param->buff);
                memset(param->buff, 0, sizeof(param->buff));
            }
            else if (!create_folder_id(config.access_token, "root", param->create_dir, folder_id))
            {
                ConfigAddString(cfg, ONEDRIVE_SECTION, ONEDRIVE_ROOT_FOLDER, folder_id);
                ConfigPrintToBuffer(cfg, param->buff);
                param->config_encryption(param->conf_file, param->key, param->buff);
                memset(param->buff, 0, sizeof(param->buff));
            }
        }
        else
        {
            printf("Search folder id failed\n");
            return -1;
        }
        return 0;
    }

    if (param->filepath == NULL)
    {
        printf("File name is not passed\n");
        return 1;
    }
    else if (strlen(config.access_token) > 0 && config.created_time > 0 && config.expired_in > 0 &&
            (now - config.created_time) < (config.expired_in - 120))
    {
        struct stat file_info;
        stat(param->filepath, &file_info);

        if (S_ISREG(file_info.st_mode))
        {
            int res;
            if(file_info.st_size > MAX_SIMPLE_UPLOAD_SIZE)
            {
                res = upload_file_chunked(config.access_token, param->filepath, param->root_dir);
            }
            else
            {
                res = upload_file_simple(config.access_token, param->filepath, param->root_dir, file_info.st_size);
            }

            if (res)
            {
                printf("Upload failed!\n");
            }
            else
            {
                char *file_list = NULL;
                printf("\n");
                if (NULL != (file_list = get_file_list(config.access_token, param->root_dir)))
                {
                    del_old_files(config.access_token, file_list);
                    free(file_list);
                }
            }
        }
        else if (S_ISDIR(file_info.st_mode))
        {
            char *dir_name = strrchr(param->filepath, '/');
            if (dir_name == NULL)
            {
                dir_name = param->filepath;
            }
            else
            {
                dir_name++;
            }

            if (!get_folder_id(config.access_token, param->root_dir, dir_name, folder_id))
            {
                if (strlen(folder_id) == 0)
                    create_folder_id(config.access_token, param->root_dir, dir_name, folder_id);
            }
        }
    }
    else
    {
        printf("Something wrong with access_token OR created_time OR expired_in\n");
        return 1;
    }

    return 0;
}

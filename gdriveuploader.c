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
#include "gdriveuploader.h"
#include "common.h"

static unsigned char debug = 0;

static int get_device_code(const char *client_id, char *device_code, char *user_code, char *url)
{
    CURL *curl;
    char getDeviceCode[] = "https://accounts.google.com/o/oauth2/device/code";

    curl = curl_easy_init();

    if(curl)
    {
        string_t response;
        char content[256] = {'\0'};
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[16]; /* We expect no more than 128 tokens */

        init_string(&response);

        sprintf(content, "client_id=%s&scope=https://docs.google.com/feeds", client_id);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, getDeviceCode);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "get get_device_code failed: %s\n", curl_easy_strerror(res));
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
                    if (!strcmp(name, "verification_url"))
                    {
                        json_get_str(&t[++i], response.ptr, url);
                    }
                    else if (!strcmp(name, "device_code"))
                    {
                        json_get_str(&t[++i], response.ptr, device_code);
                    }
                    else if (!strcmp(name, "user_code"))
                    {
                        json_get_str(&t[++i], response.ptr, user_code);
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

static int get_refresh_token(const char *client_id, const char *client_secret, const char *device_code,
        char *refresh_token, char *access_token, int *expired_in)
{
    CURL *curl;
    char getRefreshToken[] = "https://accounts.google.com/o/oauth2/token";
    char error_str[64];

    curl = curl_easy_init();

    if(curl)
    {
        string_t response;
        char content[512] = {'\0'};
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[16]; /* We expect no more than 128 tokens */

        init_string(&response);

        sprintf(content, "client_id=%s&client_secret=%s&code=%s&grant_type=http://oauth.net/grant_type/device/1.0",
                client_id, client_secret, device_code);

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
                    if (!strcmp(name, "access_token"))
                    {
                        json_get_str(&t[++i], response.ptr, access_token);
                    }
                    else if (!strcmp(name, "refresh_token"))
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

static int get_folder_id(const char *access_token, const char *folderid,
        const char *foldername, char *folderid_res)
{
    CURL *curl;

    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char header_token[128] = {'\0'};
        char link[256] = {'\0'};
        string_t response;
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[16]; /* We expect no more than 128 tokens */

        char *output = curl_easy_escape(curl, foldername, strlen(foldername));
        init_string(&response);

        sprintf(header_token, "Authorization: Bearer %s", access_token);
        sprintf(link, "https://www.googleapis.com/drive/v2/files/%s/children?orderBy=title&"
                "q=mimeType%%3D'application%%2Fvnd.google-apps.folder'%%20and%%20title%%3D'%s'&"
                "fields=items%%2Fid", folderid, output);
        curl_free(output);

        chunk = curl_slist_append(chunk, "Host: www.googleapis.com");
        chunk = curl_slist_append(chunk, header_token);

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
            for (i = 0 ; i < ret ; i++)
            {
                if(t[i].type == JSMN_STRING) // must be key
                {
                    json_get_str(&t[i], response.ptr, name);
                    if (!strcmp(name, "items"))
                    {
                        if(t[i + 1].type == JSMN_ARRAY)
                        {
                            if (t[i + 1].size > 0)
                            {
                                i++;
                            }
                            else
                            {
                                ret = 0;
                                break;
                            }
                        }
                    }
                    else if (!strcmp(name, "id"))
                    {
                        json_get_str(&t[i + 1], response.ptr, folderid_res);
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

static int create_folder_id(const char *access_token, const char *folderid,
        const char *foldername, char *folderid_res)
{
    CURL *curl;
    char getFolderId[] = "https://www.googleapis.com/drive/v2/files?fields=id";

    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char header_token[128] = {'\0'};
        char content[256] = {'\0'};
        char content_len[32] = {'\0'};
        string_t response;
        CURLcode res;

        int ret, i;
        jsmn_parser p;
        char name[32];
        jsmntok_t t[16]; /* We expect no more than 128 tokens */

        init_string(&response);

        sprintf(header_token, "Authorization: Bearer %s", access_token);
        sprintf(content, "{\"mimeType\": \"application/vnd.google-apps.folder\",\"title\": \"%s\",\"parents\": [{\"id\": \"%s\"}]}",
                foldername, folderid);
        sprintf(content_len, "Content-Length: %ld", strlen(content));

        chunk = curl_slist_append(chunk, "Host: www.googleapis.com");
        chunk = curl_slist_append(chunk, header_token);
        chunk = curl_slist_append(chunk, "Content-Type: application/json; charset=UTF-8");
        chunk = curl_slist_append(chunk, content_len);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, getFolderId);
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
                    if (!strcmp(name, "id"))
                    {
                        json_get_str(&t[i + 1], response.ptr, folderid_res);
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

static int get_access_token(const char *client_id, const char *client_secret,
        const char *refresh_token, char *access_token, int *expired_time)
{
    CURL *curl;
    char getAccessToken[] = "https://accounts.google.com/o/oauth2/token";
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

        chunk = curl_slist_append(chunk, "Host: accounts.google.com");
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
                    if (!strcmp(name,"access_token"))
                    {
                        json_get_str(&t[++i], response.ptr, access_token);
                    }
                    else if (!strcmp(name,"expires_in"))
                    {
                        json_get_int(&t[++i], response.ptr, expired_time);
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

static int get_link_upload(const char *access_token, const char *filepath,
        curl_off_t filesize, const char *folderid, char *link)
{
    CURL *curl;
    char getLinkUpload[] = "https://www.googleapis.com/upload/drive/v2/files?uploadType=resumable";

    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char header_token[128] = {'\0'};
        char header_mime[64] = {'\0'};
        char file_size[64] = {'\0'};
        char content[256] = {'\0'};
        char mime_type[32] = {'\0'};
        char content_len[32] = {'\0'};
        string_t header;
        char *location = NULL;
        const char *file_name = NULL;
        CURLcode res;

        init_string(&header);
        file_name = strrchr(filepath, '/');
        if (file_name == NULL)
        {
            file_name = filepath;
        }
        else
        {
            file_name++;
        }

        sprintf(header_token, "Authorization: Bearer %s", access_token);
        if (strstr(file_name, ".mp4"))
        {
            strcpy(mime_type, "video/mp4");
        }
        else if (strstr(file_name, ".flv"))
        {
            strcpy(mime_type, "video/flv");
        }
        else if (strstr(file_name, ".jpg"))
        {
            strcpy(mime_type, "image/jpeg");
        }
        else
        {
            strcpy(mime_type, "text/plain");
        }
        sprintf(header_mime, "X-Upload-Content-Type: %s", mime_type);
        sprintf(file_size, "X-Upload-Content-Length: %ld", filesize);
        sprintf(content, "{\"mimeType\": \"%s\",\"title\": \"%s\",\"parents\": [{\"id\": \"%s\"}]}",
                mime_type, file_name, folderid);
        sprintf(content_len, "Content-Length: %ld", strlen(content));

        chunk = curl_slist_append(chunk, "Host: www.googleapis.com");
        chunk = curl_slist_append(chunk, header_token);
        chunk = curl_slist_append(chunk, "Content-Type: application/json; charset=UTF-8");
        chunk = curl_slist_append(chunk, header_mime);
        chunk = curl_slist_append(chunk, file_size);
        chunk = curl_slist_append(chunk, content_len);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, content);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_URL, getLinkUpload);
        if (debug)
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);

        if(res != CURLE_OK)
        {
            fprintf(stderr, "get get_link_upload failed: %s\n", curl_easy_strerror(res));
            return res;
        }

        if ((location = strstr(header.ptr, "Location:")))
        {
            sscanf(location + 9, "%s", link);
        }
        free(header.ptr);

        return 0;
    }
    return 1;
}

static int upload_file(const char *access_token, const char *filepath,
        curl_off_t filesize, const char *link)
{
    CURL *curl;

    FILE *fp = fopen(filepath, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "open file %s failed\n", filepath);
        return 1;
    }
    curl = curl_easy_init();

    if(curl)
    {
        struct curl_slist *chunk = NULL;
        char header_token[128] = {'\0'};
        char header_mime[64] = {'\0'};
        char file_size[64] = {'\0'};
        char header_file[256] = {'\0'};
        char mime_type[32] = {'\0'};
        const char *file_name = NULL;
        CURLcode res;

        file_name = strrchr(filepath, '/');
        if (file_name == NULL)
        {
            file_name = filepath;
        }
        else
        {
            file_name++;
        }

        sprintf(header_token, "Authorization: Bearer %s", access_token);
        if (strstr(file_name, ".mp4"))
        {
            strcpy(mime_type, "video/mp4");
        }
        else if (strstr(file_name, ".flv"))
        {
            strcpy(mime_type, "video/flv");
        }
        else if (strstr(file_name, ".jpg"))
        {
            strcpy(mime_type, "image/jpeg");
        }
        else
        {
            strcpy(mime_type, "text/plain");
        }
        sprintf(header_mime, "Content-Type: %s", mime_type);
        sprintf(file_size, "Content-Length: %ld", filesize);
        sprintf(header_file, "Slug: %s", file_name);

        chunk = curl_slist_append(chunk, "Host: www.googleapis.com");
        chunk = curl_slist_append(chunk, header_token);
        chunk = curl_slist_append(chunk, header_mime);
        chunk = curl_slist_append(chunk, file_size);
        chunk = curl_slist_append(chunk, header_file);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_PUT, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, fp);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, filesize);
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
        char header_token[128] = {'\0'};
        char link[256] = {'\0'};
        string_t response;
        CURLcode res;

        init_string(&response);

        sprintf(header_token, "Authorization: Bearer %s", access_token);
        sprintf(link, "https://www.googleapis.com/drive/v2/files?"
                "q='%s'+in+parents+and+trashed%%3Dfalse&fields=items(id,title,createdDate)", folder_id);

        chunk = curl_slist_append(chunk, "Host: www.googleapis.com");
        chunk = curl_slist_append(chunk, header_token);

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
        char header_token[128] = {'\0'};
        char link[256] = {'\0'};
        CURLcode res;

        sprintf(header_token, "Authorization: Bearer %s", access_token);
        sprintf(link, "https://www.googleapis.com/drive/v2/files/%s", file_id);

        chunk = curl_slist_append(chunk, "Host: www.googleapis.com");
        chunk = curl_slist_append(chunk, header_token);

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
    while(NULL != (tmp = strstr(tmp, "title")))
    {
       count++;
       tmp++;
    }

    t = (jsmntok_t *)malloc(sizeof(jsmntok_t) * (count * 7 + 3));
    jsmn_init(&p);
    ret = jsmn_parse(&p, json_str, strlen(json_str), t, count * 7 + 3);
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
        char store[256] = {'\0'};
        char date[9] = {'\0'};
        count = 0;

        for (i = 0; i < ret; i++)
        {
            if(t[i].type == JSMN_STRING && t[i].size == 1) // must be key
            {
                json_get_str(&t[i], json_str, key);
                if (!strcmp(key, "title"))
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
                else if (!strcmp(key, "items"))
                {
                    if (t[i + 1].type == JSMN_ARRAY && t[i + 1].size > 0)
                        i++;
                }
            }
        }

        if (count == (MAX_EVENT + 1))
        {
            unsigned char is_wait_id = 0;
            store[0] = '\0';

            for (i = i - ((i - 3) % 7); i < ret; i++)
            {
                if(t[i].type == JSMN_STRING && t[i].size == 1 ) // must be key
                {
                    json_get_str(&t[i], json_str, key);
                    if (!strcmp(key, "id"))
                    {
                        json_get_str(&t[++i], json_str, val);
                        if (is_wait_id)
                        {
                            delete_file(access_token, val);
                            is_wait_id = 0;
                        }
                        else
                        {
                            strcpy(store, val);
                            store[strlen(val)] = '\0';
                        }
                    }
                    else if (!strcmp(key, "title"))
                    {
                        json_get_str(&t[++i], json_str, val);
                        if (strlen(val) > 33)
                        {
                            strncpy(date, val + 16, 8);
                            if (!date_validate(date))
                            {
                                if (strlen(store) > 0)
                                {
                                    delete_file(access_token, store);
                                    store[0] = '\0';
                                    is_wait_id = 0;
                                }
                                else
                                    is_wait_id = 1;
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

int gdrive(Config *cfg, params_t *param, uint8_t d)
{
    google_config_t config;
    char folder_id[32] = {'\0'};
    char device_code[128] = {'\0'};
    char user_code[16] = {'\0'};
    char url[64] = {'\0'};
    time_t now = time(0);
    debug = d;

    memset(&config, 0, sizeof(google_config_t));

    ConfigReadString(cfg, GOOGLE_SECTION, GOOGLE_CLIENT_ID, config.client_id, sizeof(config.client_id), "");
    ConfigReadString(cfg, GOOGLE_SECTION, GOOGLE_CLIENT_SECRET, config.client_secret, sizeof(config.client_secret), "");
    ConfigReadString(cfg, GOOGLE_SECTION, GOOGLE_REFRESH_TOKEN, config.refresh_token, sizeof(config.refresh_token), "");
    ConfigReadString(cfg, GOOGLE_SECTION, GOOGLE_ROOT_FOLDER, config.root_folder, sizeof(config.root_folder), "root");
    ConfigReadString(cfg, GOOGLE_SECTION, GOOGLE_ACCESS_TOKEN, config.access_token, sizeof(config.access_token), "");
    ConfigReadUnsignedInt(cfg, GOOGLE_SECTION, GOOGLE_CREATED_TIME, &config.created_time, 0);
    ConfigReadInt(cfg, GOOGLE_SECTION, GOOGLE_EXPIRED_IN, &config.expired_in, 0);

    if (param->root_dir == NULL)
    {
        param->root_dir = config.root_folder;
    }
    else
    {
        ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_ROOT_FOLDER, param->root_dir);
        ConfigPrintToBuffer(cfg, param->buff);
        param->config_encryption(param->conf_file, param->key, param->buff);
        memset(param->buff, 0, sizeof(param->buff));
    }

    if(param->is_reauth)
    {
        if (!get_device_code(config.client_id, device_code, user_code, url))
        {
            ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_REFRESH_TOKEN, "");
            ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_ACCESS_TOKEN, "");
            ConfigPrintToBuffer(cfg, param->buff);
            param->config_encryption(param->conf_file, param->key, param->buff);
            memset(param->buff, 0, sizeof(param->buff));

            printf("Go to %s and enter %s to grant access to this application. Hit enter when done...", url, user_code);
            getchar();
            if(!get_refresh_token(config.client_id, config.client_secret, device_code,
                    config.refresh_token, config.access_token, &config.expired_in))
            {
                if (!strlen(config.refresh_token))
                {
                    printf("Cannot get refresh token\n");
                    return 1;
                }
                config.created_time = now;
                ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_REFRESH_TOKEN, config.refresh_token);
                ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_ACCESS_TOKEN, config.access_token);
                ConfigAddUnsignedInt(cfg, GOOGLE_SECTION, GOOGLE_CREATED_TIME, config.created_time);
                ConfigAddInt(cfg, GOOGLE_SECTION, GOOGLE_EXPIRED_IN, config.expired_in);
                ConfigPrintToBuffer(cfg, param->buff);
                param->config_encryption(param->conf_file, param->key, param->buff);
                memset(param->buff, 0, sizeof(param->buff));
                return 0;
            }
            else
            {
                printf("Get refresh token failed\n");
                return 1;
            }
        }
        else
        {
            printf("Get device code failed\n");
            return 1;
        }
    }

    if (!strlen(config.refresh_token))
    {
        if (!get_device_code(config.client_id, device_code, user_code, url))
        {
            printf("Go to %s and enter %s to grant access to this application. Hit enter when done...", url, user_code);
            getchar();
            if(!get_refresh_token(config.client_id, config.client_secret, device_code,
                    config.refresh_token, config.access_token, &config.expired_in))
            {
                if (!strlen(config.refresh_token))
                {
                    printf("Cannot get refresh token\n");
                    return 1;
                }
                config.created_time = now;
                ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_REFRESH_TOKEN, config.refresh_token);
                ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_ACCESS_TOKEN, config.access_token);
                ConfigAddUnsignedInt(cfg, GOOGLE_SECTION, GOOGLE_CREATED_TIME, config.created_time);
                ConfigAddInt(cfg, GOOGLE_SECTION, GOOGLE_EXPIRED_IN, config.expired_in);
                ConfigPrintToBuffer(cfg, param->buff);
                param->config_encryption(param->conf_file, param->key, param->buff);
                memset(param->buff, 0, sizeof(param->buff));
            }
            else
            {
                printf("Get refresh token failed\n");
                return -1;
            }
        }
        else
        {
            printf("Get device code failed\n");
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
        ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_ACCESS_TOKEN, config.access_token);
        ConfigAddUnsignedInt(cfg, GOOGLE_SECTION, GOOGLE_CREATED_TIME, config.created_time);
        ConfigAddInt(cfg, GOOGLE_SECTION, GOOGLE_EXPIRED_IN, config.expired_in);
        ConfigPrintToBuffer(cfg, param->buff);
        param->config_encryption(param->conf_file, param->key, param->buff);
        memset(param->buff, 0, sizeof(param->buff));
    }
    if (param->create_dir != NULL && strlen(config.access_token) > 0 && config.created_time > 0 &&
            config.expired_in > 0 && (now - config.created_time) < (config.expired_in - 120))
    {
        if (!get_folder_id(config.access_token, "root", param->create_dir, folder_id))
        {
            if (strlen(folder_id) > 0)
            {
                printf("Folder '%s' have already existed in root\n", param->create_dir);
                ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_ROOT_FOLDER, folder_id);
                ConfigPrintToBuffer(cfg, param->buff);
                param->config_encryption(param->conf_file, param->key, param->buff);
                memset(param->buff, 0, sizeof(param->buff));
            }
            else if (!create_folder_id(config.access_token, "root", param->create_dir, folder_id))
            {
                ConfigAddString(cfg, GOOGLE_SECTION, GOOGLE_ROOT_FOLDER, folder_id);
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
            char link_upload[256] = {'\0'};
            if (!get_link_upload(config.access_token, param->filepath, (curl_off_t)file_info.st_size, param->root_dir, link_upload))
            {
                if (upload_file(config.access_token, param->filepath, (curl_off_t)file_info.st_size, link_upload))
                {
                    printf("Upload failed!\n");
                }
                else
                {
                    char *file_list = NULL;
                    if (NULL != (file_list = get_file_list(config.access_token, param->root_dir)))
                    {
                        del_old_files(config.access_token, file_list);
                        free(file_list);
                    }
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

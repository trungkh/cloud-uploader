/*
 * Copyright (c) 2016 · Trung Huynh
 */

#include "common.h"

int date_validate(char *date)
{
    int dd,mm,yy;
    char d[9] = {'\0'};

    strcpy(d, date);
    dd = atoi(d + 6);
    d[6] = '\0';
    mm = atoi(d + 4);
    d[4] = '\0';
    yy = atoi(d + 0);

    if(yy>=1900 && yy<=9999)
    {
        if(mm>=1 && mm<=12)
        {
            if((dd>=1 && dd<=31) && (mm==1 || mm==3 || mm==5 || mm==7 || mm==8 || mm==10 || mm==12))
                return 0;
            else if((dd>=1 && dd<=30) && (mm==4 || mm==6 || mm==9 || mm==11))
                return 0;
            else if((dd>=1 && dd<=28) && (mm==2))
                return 0;
            else if(dd==29 && mm==2 && (yy%400==0 ||(yy%4==0 && yy%100!=0)))
                return 0;
            else
                return 3;
        }
        else
        {
            return 2;
        }
    }
    else
    {
        return 1;
    }
}

void init_string(string_t *s)
{
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr == NULL)
    {
        fprintf(stderr, "init_string failed\n");
        exit(1);
    }
    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, string_t *s)
{
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL)
    {
        fprintf(stderr, "realloc() failed\n");
        exit(1);
    }
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size * nmemb;
}

size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t retcode;

    retcode = fread(ptr, size, nmemb, stream);

    fprintf(stderr, "*** Read %ld bytes from file\n", retcode);

    return retcode;
}

void json_get_str(jsmntok_t *t, const char *data, char *name)
{
    int len = t->end - t->start;
    memcpy(name, data + t->start, len);
    name[len] = '\0';
}

void json_get_int(jsmntok_t *t, const char *data, int *number)
{
    char str[10] = {'\0'};
    int len = t->end - t->start;
    memcpy(str, data + t->start, len);

    *number = atoi(str);
}

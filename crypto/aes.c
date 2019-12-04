/*
 * Copyright (c) 2013 · leon
 * DESC   : Contain all hanlde about AES encrypt
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>

#include "aes_sw.h"
#include "aes.h"

typedef struct tAESInternalBuf
{
    void* data;
    size_t size;
} tAESInternalBuf;

static char encryptMode[16] = { 'c', 'b', 'c', 0 };
//static tAESInternalBuf  hwEncBuffer = {0, 0};
static tAESInternalBuf swEncBuf = { 0, 0 };
static tAESInternalBuf swDecBuf = { 0, 0 };

/*
 * PURPOSE : Encrypt data with specify key using software engine
 * INPUT   : [key]     - aes key
 *           [iv]      - initialize vector
 *           [dataIn]  - data need to encrypt
 *           [iSize]   - size of data input
 * OUTPUT  : [oSize]   - size of data encrypted
 * RETURN  : Pointer to encrypted data
 * DESCRIPT: Wrapper function. User must free return pointer after use
 */
uint8_t*
aes_sw_encrypt(uint8_t* key, uint8_t* iv, uint8_t* dataIn, size_t iSize,
        size_t* oSize)
{
    aes_context sw_ctx;

    //Check input params
    if (key == NULL || dataIn == NULL)
    {
        //mylog_error("[AES_SW] - Input params is NULL");
        *oSize = 0;
        return NULL;
    }

    //Initialize software AES engine
    if (aes_set_key(&sw_ctx, key, _AES_MAX_KEY_SIZE_, encryptMode))
    {
        //mylog_error("[AES_SW] - aes_set_key failed");
        *oSize = 0;
        return NULL;
    }

    //Prepare buffer
    if (swEncBuf.size < (*oSize))
    {
        swEncBuf.data = (void*) realloc(swEncBuf.data,
                sizeof(uint8_t) * (*oSize));
        if (swEncBuf.data != NULL)
            swEncBuf.size = (*oSize);
    }

    if (swEncBuf.data != NULL)
    {
        memset(swEncBuf.data, 0, (*oSize));
        memcpy(swEncBuf.data, dataIn, iSize);
        //Encrypt using software
        aes_encrypt(&sw_ctx, iv, swEncBuf.data, iSize);
        *oSize = iSize;
    }
    return swEncBuf.data;
}

/*
 * PURPOSE : Decrypt data with specify key using software engine
 * INPUT   : [key]     - aes key
 *           [iv]      - initialize vector
 *           [dataIn]  - data need to decrypt
 *           [iSize]   - size of data input
 * OUTPUT  : [oSize]   - size of data decrypted
 * RETURN  : Pointer to decrypted data
 * DESCRIPT: Wrapper function. User must free return pointer after use
 */
uint8_t*
aes_sw_decrypt(uint8_t* key, uint8_t* iv, uint8_t* dataIn, size_t iSize,
        size_t* oSize)
{
    aes_context sw_ctx;

    //Check input params
    if (key == NULL || dataIn == NULL)
    {
        //mylog_error("[AES_SW] - Input params is NULL");
        *oSize = 0;
        return NULL;
    }

    //Initialize software AES engine
    if (aes_set_key(&sw_ctx, key, _AES_MAX_KEY_SIZE_, encryptMode))
    {
        //mylog_error("[AES_SW] - aes_set_key failed");
        *oSize = 0;
        return NULL;
    }

    //Prepare buffer
    if (swDecBuf.size < (*oSize))
    {
        swDecBuf.data = (void*) realloc(swDecBuf.data,
                sizeof(uint8_t) * (*oSize));
        if (swDecBuf.data != NULL)
            swDecBuf.size = (*oSize);
    }

    if (swDecBuf.data != NULL)
    {
        memset(swDecBuf.data, 0, (*oSize));
        memcpy(swDecBuf.data, dataIn, iSize);
        //Decrypt using software
        aes_decrypt(&sw_ctx, iv, swDecBuf.data, iSize);
        *oSize = iSize;
    }
    return swDecBuf.data;
}

/*
 * DATE   : 2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "encrypt.h"
#include "aes.h"

#define DEF_AES_KEY_SIZE                16
#define DEF_AES_IV_SIZE                 16

static uint8_t gAlawDataEncryptKey[DEF_AES_KEY_SIZE] =
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static uint8_t gAlawDataEncryptIV[DEF_AES_IV_SIZE] =
    { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 };

/*
 * PURPOSE : Fast encrypt an alaw frame
 * INPUT   : [key]         - AES Key
 *           [iv]          - AES Initialize vector
 *           [data]    - Frame lain data
 *           [length]  - Frame length
 * OUTPUT  : [data]    - Frame encrypted
 * RETURN  : The encrypted data length
 * DESCRIPT: None
 */
static size_t alawDataEncrypt(uint8_t* key, uint8_t* iv, uint8_t* data,
        size_t length)
{
    size_t outLength = 0;
    uint8_t *outData = NULL;
    outLength = length;
    outData = aes_sw_encrypt(key, iv, data, length, &outLength);
    if (outLength <= length)
    {
        memcpy(data, outData, outLength);
        return outLength;
    }
    return -1;
}

/*
 * PURPOSE : Wrapper function to encrypt a alaw frame
 * INPUT   : [frame]       - Pointer to frame data
 *           [frameLength] - Length of frame
 * OUTPUT  : None
 * RETURN  : Encrypted data length
 * DESCRIPT: This will encrypt directly from frame data
 */
size_t alawEncryptWrapper(void* frame, size_t frameLength)
{
    return alawDataEncrypt(gAlawDataEncryptKey, gAlawDataEncryptIV, frame,
            frameLength);
}

/*
 * PURPOSE : Init key and iv vector use for encypt
 * INPUT   : [model] - Model name of product
 * OUTPUT  : None
 * RETURN  : 0 if success
 * DESCRIPT: None
 */
int alawEncryptKeyInit(char *key, char *iv)
{
    /* Init key */
    bzero(gAlawDataEncryptKey, DEF_AES_KEY_SIZE);
    memcpy(gAlawDataEncryptKey, key, DEF_AES_KEY_SIZE);

    /* Init IV */
    bzero(gAlawDataEncryptIV, DEF_AES_IV_SIZE);
    memcpy(gAlawDataEncryptIV, iv, DEF_AES_IV_SIZE);
    return 0;
}

/*
 * PURPOSE : Get time stamp at micro-seconds
 * INPUT   : None
 * OUTPUT  : None
 * RETURN  : Time stamp
 * DESCRIPT: None
 */
uint32_t alawEncryptUsTimeGet()
{
    uint32_t ret = 0;
    struct timespec t = { 0 };

    if (clock_gettime(0, &t) == 0)
        ret = t.tv_sec * 1000000 + t.tv_nsec / 1000;
    return ret;
}

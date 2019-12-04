/*
 * Copyright (c) 2013 · leon
 * DESC   : Contain all hanlde about AES encrypt
 */

#ifndef AES_H_
#define AES_H_

#define _AES_KEY_SEARCH_KEYWORD_  "master_key"
#define _AES_KEY_MAX_BYTES_LEN_   16  //bytes
#define _AES_MAX_KEY_SIZE_        128 //bit
#define _AES_IV_SIZE_             16
#define _AES_BLK_SIZE_            16
#define _AES_KEY_CONVERT_TO_HEX   0

/*
 * PURPOSE : Encrypt data with specify key using hardware engine
 * INPUT   : [key]     - aes key
 *           [iv]      - initialize vector
 *           [dataIn]  - data need to encrypt
 *           [iSize]   - size of data input
 * OUTPUT  : [oSize]   - size of data encrypted
 * RETURN  : Pointer to encrypted data
 * DESCRIPT: Wrapper function. User must free return pointer after use
 */
uint8_t*
aes_sw_encrypt(uint8_t* key, uint8_t* iv, uint8_t* dataIn, size_t iSize, size_t* oSize);

uint8_t*
aes_sw_decrypt(uint8_t* key, uint8_t* iv, uint8_t* dataIn, size_t iSize, size_t* oSize);

#endif /* AES_H_ */

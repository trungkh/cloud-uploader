/*
 * DATE   : 2014
 */
#ifndef DECRYPT_H_
#define DECRYPT_H_

/*
 * PURPOSE : Wrapper function to encrypt a alaw frame
 * INPUT   : [frame]       - Pointer to frame data
 *           [frameLength] - Length of frame
 * OUTPUT  : None
 * RETURN  : DECRYPTed data length
 * DESCRIPT: This will encrypt directly from frame data
 */
size_t
alawDecryptWrapper(void* frame, size_t frameLength);

/*
 * PURPOSE : Init key and iv vector use for encypt
 * INPUT   : [model] - Model name of product
 * OUTPUT  : None
 * RETURN  : 0 if success
 * DESCRIPT: None
 */
int
alawDecryptKeyInit();

/*
 * PURPOSE : Get time stamp at micro-seconds
 * INPUT   : None
 * OUTPUT  : None
 * RETURN  : Time stamp
 * DESCRIPT: None
 */
//unsigned int alawEncryptUsTimeGet();



#endif /* ENCRYPT_H_ */

/*
 * DATE   : 2014
 */
#ifndef ENCRYPT_H_
#define ENCRYPT_H_

/*
 * PURPOSE : Wrapper function to encrypt a alaw frame
 * INPUT   : [frame]       - Pointer to frame data
 *           [frameLength] - Length of frame
 * OUTPUT  : None
 * RETURN  : Encrypted data length
 * DESCRIPT: This will encrypt directly from frame data
 */
size_t
alawEncryptWrapper(void* frame, size_t frameLength);

/*
 * PURPOSE : Init key and iv vector use for encypt
 * INPUT   : [model] - Model name of product
 * OUTPUT  : None
 * RETURN  : 0 if success
 * DESCRIPT: None
 */
int
alawEncryptKeyInit();

/*
 * PURPOSE : Get time stamp at micro-seconds
 * INPUT   : None
 * OUTPUT  : None
 * RETURN  : Time stamp
 * DESCRIPT: None
 */
unsigned int alawEncryptUsTimeGet();

#endif /* ENCRYPT_H_ */

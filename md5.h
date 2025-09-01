
#ifndef MD5_H__
#define MD5_H__

#ifdef __cplusplus
extern "C" {
#endif

void MD5(const void* buf, unsigned int len, unsigned char output[16]);

#ifdef __cplusplus
}
#endif

#endif
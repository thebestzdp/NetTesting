/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_KRYPTON_KRYPTON_H_
#define CS_KRYPTON_KRYPTON_H_

#ifdef KR_LOCALS
#include <kr_locals.h>
#endif

typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st CSSL_CTX;
typedef struct ssl_method_st CSSL_METHOD;

int CSSL_library_init(void);
SSL *CSSL_new(CSSL_CTX *ctx);
int CSSL_set_fd(SSL *ssl, int fd);
int CSSL_accept(SSL *ssl);
int CSSL_connect(SSL *ssl);
int CSSL_read(SSL *ssl, void *buf, int num);
int CSSL_write(SSL *ssl, const void *buf, int num);
int CSSL_shutdown(SSL *ssl);
void CSSL_free(SSL *ssl);

#define CSSL_ERROR_NONE 0
#define CSSL_ERROR_SSL 1
#define CSSL_ERROR_WANT_READ 2
#define CSSL_ERROR_WANT_WRITE 3
#define CSSL_ERROR_SYSCALL 5
#define CSSL_ERROR_ZERO_RETURN 6
#define CSSL_ERROR_WANT_CONNECT 7
#define CSSL_ERROR_WANT_ACCEPT 8
int CSSL_get_error(const SSL *ssl, int ret);

const CSSL_METHOD *CSSLv23_client_method(void);

CSSL_CTX *CSSL_CTX_new(const CSSL_METHOD *meth);

long CSSL_CTX_ctrl(CSSL_CTX *, int, long, void *);

void CSSL_CTX_free(CSSL_CTX *);

typedef struct {
  unsigned char block_len;
  unsigned char key_len;
  unsigned char iv_len;
  void *(*new_ctx)();
  void (*setup_enc)(void *ctx, const unsigned char *key);
  void (*setup_dec)(void *ctx, const unsigned char *key);
  void (*encrypt)(void *ctx, const unsigned char *msg, int len, unsigned char *out);
  void (*decrypt)(void *ctx, const unsigned char *msg, int len, unsigned char *out);
  void (*free_ctx)(void *ctx);
} kr_cipher_info;

#endif /* CS_KRYPTON_KRYPTON_H_ */

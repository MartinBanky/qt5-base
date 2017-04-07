/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Copyright (C) 2014 BlackBerry Limited. All rights reserved.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

/****************************************************************************
**
** In addition, as a special exception, the copyright holders listed above give
** permission to link the code of its release of Qt with the OpenSSL project's
** "OpenSSL" library (or modified versions of the "OpenSSL" library that use the
** same license as the original version), and distribute the linked executables.
**
** You must comply with the GNU General Public License version 2 in all
** respects for all of the code used other than the "OpenSSL" code.  If you
** modify this file, you may extend this exception to your version of the file,
** but you are not obligated to do so.  If you do not wish to do so, delete
** this exception statement from your version of this file.
**
****************************************************************************/

#ifndef QSSLSOCKET_OPENSSL_SYMBOLS_P_H
#define QSSLSOCKET_OPENSSL_SYMBOLS_P_H

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API. It exists purely as an
// implementation detail. This header file may change from version to
// version without notice, or even be removed.
//
// We mean it.
//

#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "qsslsocket_openssl_p.h"
#include <QtCore/qglobal.h>

#include <openssl/opensslconf.h>

QT_BEGIN_NAMESPACE

#define DUMMYARG

#if !defined QT_LINKED_OPENSSL
// **************** Shared declarations ******************
// ret func(arg)

#  define DEFINEFUNC(ret, func, arg, a, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg); \
    static _q_PTR_##func _q_##func = 0; \
    ret q_##func(arg) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a); \
    }

// ret func(arg1, arg2)
#  define DEFINEFUNC2(ret, func, arg1, a, arg2, b, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2);         \
    static _q_PTR_##func _q_##func = 0;               \
    ret q_##func(arg1, arg2) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func);\
            err; \
        } \
        funcret _q_##func(a, b); \
    }

// ret func(arg1, arg2, arg3)
#  define DEFINEFUNC3(ret, func, arg1, a, arg2, b, arg3, c, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3);            \
    static _q_PTR_##func _q_##func = 0;                        \
    ret q_##func(arg1, arg2, arg3) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c); \
    }

// ret func(arg1, arg2, arg3, arg4)
#  define DEFINEFUNC4(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4);               \
    static _q_PTR_##func _q_##func = 0;                                 \
    ret q_##func(arg1, arg2, arg3, arg4) { \
         if (Q_UNLIKELY(!_q_##func)) { \
             qsslSocketUnresolvedSymbolWarning(#func); \
             err; \
         } \
         funcret _q_##func(a, b, c, d); \
    }

// ret func(arg1, arg2, arg3, arg4, arg5)
#  define DEFINEFUNC5(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5);         \
    static _q_PTR_##func _q_##func = 0;                                 \
    ret q_##func(arg1, arg2, arg3, arg4, arg5) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c, d, e); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6)
#  define DEFINEFUNC6(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6);   \
    static _q_PTR_##func _q_##func = 0;                                 \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c, d, e, f); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7)
#  define DEFINEFUNC7(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7);   \
    static _q_PTR_##func _q_##func = 0;                                       \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c, d, e, f, g); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7, arg8, arg9)
#  define DEFINEFUNC9(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, arg8, h, arg9, i, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);   \
    static _q_PTR_##func _q_##func = 0;                                                   \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        }   \
        funcret _q_##func(a, b, c, d, e, f, g, h, i); \
    }
// **************** Shared declarations ******************

#else // !defined QT_LINKED_OPENSSL

// **************** Static declarations ******************

// ret func(arg)
#  define DEFINEFUNC(ret, func, arg, a, err, funcret) \
    ret q_##func(arg) { funcret func(a); }

// ret func(arg1, arg2)
#  define DEFINEFUNC2(ret, func, arg1, a, arg2, b, err, funcret) \
    ret q_##func(arg1, arg2) { funcret func(a, b); }

// ret func(arg1, arg2, arg3)
#  define DEFINEFUNC3(ret, func, arg1, a, arg2, b, arg3, c, err, funcret) \
    ret q_##func(arg1, arg2, arg3) { funcret func(a, b, c); }

// ret func(arg1, arg2, arg3, arg4)
#  define DEFINEFUNC4(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4) { funcret func(a, b, c, d); }

// ret func(arg1, arg2, arg3, arg4, arg5)
#  define DEFINEFUNC5(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5) { funcret func(a, b, c, d, e); }

// ret func(arg1, arg2, arg3, arg4, arg6)
#  define DEFINEFUNC6(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6) { funcret func(a, b, c, d, e, f); }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7)
#  define DEFINEFUNC7(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7) { funcret func(a, b, c, d, e, f, g); }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7, arg8, arg9)
#  define DEFINEFUNC9(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, arg8, h, arg9, i, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) { funcret func(a, b, c, d, e, f, g, h, i); }

// **************** Static declarations ******************

#endif // !defined QT_LINKED_OPENSSL

bool q_resolveOpenSslSymbols();
long q_ASN1_INTEGER_get(ASN1_INTEGER *a);
unsigned char * q_ASN1_STRING_data(ASN1_STRING *a);
int q_ASN1_STRING_length(ASN1_STRING *a);
int q_ASN1_STRING_to_UTF8(unsigned char **a, ASN1_STRING *b);
long q_BIO_ctrl(BIO *a, int b, long c, void *d);
BIO *q_BIO_new_file(const char *filename, const char *mode);
void q_ERR_clear_error();
void q_OPENSSL_free(void *ptr);
Q_AUTOTEST_EXPORT int q_BIO_free(BIO *a);
Q_AUTOTEST_EXPORT BIO *q_BIO_new(BIO_METHOD *a);
BIO *q_BIO_new_mem_buf(void *a, int b);
int q_BIO_read(BIO *a, void *b, int c);
Q_AUTOTEST_EXPORT BIO_METHOD *q_BIO_s_mem();
Q_AUTOTEST_EXPORT int q_BIO_write(BIO *a, const void *b, int c);
int q_BN_num_bits(const BIGNUM *a);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int q_BN_is_word(BIGNUM *a, BN_ULONG w);
#else
// BN_is_word is implemented purely as a
// macro in OpenSSL < 1.1. It doesn't
// call any functions.
//
// The implementation of BN_is_word is
// 100% the same between 1.0.0, 1.0.1
// and 1.0.2.
//
// Users are required to include <openssl/bn.h>.
#define q_BN_is_word BN_is_word
#endif // OPENSSL_VERSION_NUMBER >= 0x10100000L
BN_ULONG q_BN_mod_word(const BIGNUM *a, BN_ULONG w);
#ifndef OPENSSL_NO_EC
const EC_GROUP* q_EC_KEY_get0_group(const EC_KEY* k);
int q_EC_GROUP_get_degree(const EC_GROUP* g);
#endif
int q_CRYPTO_num_locks();
void q_CRYPTO_set_locking_callback(void (*a)(int, int, const char *, int));
void q_CRYPTO_set_id_callback(unsigned long (*a)());
void q_CRYPTO_free(void *a);
DSA *q_DSA_new();
void q_DSA_free(DSA *a);
X509 *q_d2i_X509(X509 **a, const unsigned char **b, long c);
char *q_ERR_error_string(unsigned long a, char *b);
unsigned long q_ERR_get_error();
unsigned long q_ERR_peek_last_error();
void q_ERR_free_strings();
void q_EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
void q_EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int q_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int q_EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int q_EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
int q_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int q_EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int q_EVP_PKEY_assign(EVP_PKEY *a, int b, void *c);
Q_AUTOTEST_EXPORT int q_EVP_PKEY_set1_RSA(EVP_PKEY *a, RSA *b);
int q_EVP_PKEY_set1_DSA(EVP_PKEY *a, DSA *b);
#ifndef OPENSSL_NO_EC
int q_EVP_PKEY_set1_EC_KEY(EVP_PKEY *a, EC_KEY *b);
#endif
void q_EVP_PKEY_free(EVP_PKEY *a);
RSA *q_EVP_PKEY_get1_RSA(EVP_PKEY *a);
DSA *q_EVP_PKEY_get1_DSA(EVP_PKEY *a);
#ifndef OPENSSL_NO_EC
EC_KEY *q_EVP_PKEY_get1_EC_KEY(EVP_PKEY *a);
#endif
int q_EVP_PKEY_type(int a);
Q_AUTOTEST_EXPORT EVP_PKEY *q_EVP_PKEY_new();
int q_i2d_X509(X509 *a, unsigned char **b);
const char *q_OBJ_nid2sn(int a);
const char *q_OBJ_nid2ln(int a);
int q_OBJ_sn2nid(const char *s);
int q_OBJ_ln2nid(const char *s);
int q_i2t_ASN1_OBJECT(char *buf, int buf_len, ASN1_OBJECT *obj);
int q_OBJ_obj2txt(char *buf, int buf_len, ASN1_OBJECT *obj, int no_name);
int q_OBJ_obj2nid(const ASN1_OBJECT *a);
#ifdef SSLEAY_MACROS
// ### verify
void *q_PEM_ASN1_read_bio(d2i_of_void *a, const char *b, BIO *c, void **d, pem_password_cb *e,
                          void *f);
// ### ditto for write
#else
Q_AUTOTEST_EXPORT EVP_PKEY *q_PEM_read_bio_PrivateKey(BIO *a, EVP_PKEY **b, pem_password_cb *c, void *d);
DSA *q_PEM_read_bio_DSAPrivateKey(BIO *a, DSA **b, pem_password_cb *c, void *d);
RSA *q_PEM_read_bio_RSAPrivateKey(BIO *a, RSA **b, pem_password_cb *c, void *d);
#ifndef OPENSSL_NO_EC
EC_KEY *q_PEM_read_bio_ECPrivateKey(BIO *a, EC_KEY **b, pem_password_cb *c, void *d);
#endif
DH *q_PEM_read_bio_DHparams(BIO *a, DH **b, pem_password_cb *c, void *d);
int q_PEM_write_bio_DSAPrivateKey(BIO *a, DSA *b, const EVP_CIPHER *c, unsigned char *d,
                                  int e, pem_password_cb *f, void *g);
int q_PEM_write_bio_RSAPrivateKey(BIO *a, RSA *b, const EVP_CIPHER *c, unsigned char *d,
                                  int e, pem_password_cb *f, void *g);
#ifndef OPENSSL_NO_EC
int q_PEM_write_bio_ECPrivateKey(BIO *a, EC_KEY *b, const EVP_CIPHER *c, unsigned char *d,
                                  int e, pem_password_cb *f, void *g);
#endif
#endif
Q_AUTOTEST_EXPORT EVP_PKEY *q_PEM_read_bio_PUBKEY(BIO *a, EVP_PKEY **b, pem_password_cb *c, void *d);
DSA *q_PEM_read_bio_DSA_PUBKEY(BIO *a, DSA **b, pem_password_cb *c, void *d);
RSA *q_PEM_read_bio_RSA_PUBKEY(BIO *a, RSA **b, pem_password_cb *c, void *d);
#ifndef OPENSSL_NO_EC
EC_KEY *q_PEM_read_bio_EC_PUBKEY(BIO *a, EC_KEY **b, pem_password_cb *c, void *d);
#endif
int q_PEM_write_bio_DSA_PUBKEY(BIO *a, DSA *b);
int q_PEM_write_bio_RSA_PUBKEY(BIO *a, RSA *b);
#ifndef OPENSSL_NO_EC
int q_PEM_write_bio_EC_PUBKEY(BIO *a, EC_KEY *b);
#endif
void q_RAND_seed(const void *a, int b);
int q_RAND_status();
RSA *q_RSA_new();
void q_RSA_free(RSA *a);
int q_sk_num(STACK *a);
void q_sk_pop_free(STACK *a, void (*b)(void *));
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
_STACK *q_sk_new_null();
void q_sk_push(_STACK *st, void *data);
void q_sk_free(_STACK *a);
void * q_sk_value(STACK *a, int b);
#else
STACK *q_sk_new_null();
void q_sk_push(STACK *st, char *data);
void q_sk_free(STACK *a);
char * q_sk_value(STACK *a, int b);
#endif
int q_SSL_accept(SSL *a);
int q_SSL_clear(SSL *a);
char *q_SSL_CIPHER_description(SSL_CIPHER *a, char *b, int c);
int q_SSL_CIPHER_get_bits(SSL_CIPHER *a, int *b);
int q_SSL_connect(SSL *a);
int q_SSL_CTX_check_private_key(const SSL_CTX *a);
long q_SSL_CTX_ctrl(SSL_CTX *a, int b, long c, void *d);
void q_SSL_CTX_free(SSL_CTX *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
SSL_CTX *q_SSL_CTX_new(const SSL_METHOD *a);
#else
SSL_CTX *q_SSL_CTX_new(SSL_METHOD *a);
#endif
int q_SSL_CTX_set_cipher_list(SSL_CTX *a, const char *b);
int q_SSL_CTX_set_default_verify_paths(SSL_CTX *a);
void q_SSL_CTX_set_verify(SSL_CTX *a, int b, int (*c)(int, X509_STORE_CTX *));
void q_SSL_CTX_set_verify_depth(SSL_CTX *a, int b);
int q_SSL_CTX_use_certificate(SSL_CTX *a, X509 *b);
int q_SSL_CTX_use_certificate_file(SSL_CTX *a, const char *b, int c);
int q_SSL_CTX_use_PrivateKey(SSL_CTX *a, EVP_PKEY *b);
int q_SSL_CTX_use_RSAPrivateKey(SSL_CTX *a, RSA *b);
int q_SSL_CTX_use_PrivateKey_file(SSL_CTX *a, const char *b, int c);
X509_STORE *q_SSL_CTX_get_cert_store(const SSL_CTX *a);
void q_SSL_free(SSL *a);
STACK_OF(SSL_CIPHER) *q_SSL_get_ciphers(const SSL *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
const SSL_CIPHER *q_SSL_get_current_cipher(SSL *a);
#else
SSL_CIPHER *q_SSL_get_current_cipher(SSL *a);
#endif
int q_SSL_version(const SSL *a);
int q_SSL_get_error(SSL *a, int b);
STACK_OF(X509) *q_SSL_get_peer_cert_chain(SSL *a);
X509 *q_SSL_get_peer_certificate(SSL *a);
long q_SSL_get_verify_result(const SSL *a);
int q_SSL_library_init();
void q_SSL_load_error_strings();
SSL *q_SSL_new(SSL_CTX *a);
long q_SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg);
int q_SSL_read(SSL *a, void *b, int c);
void q_SSL_set_bio(SSL *a, BIO *b, BIO *c);
void q_SSL_set_accept_state(SSL *a);
void q_SSL_set_connect_state(SSL *a);
int q_SSL_shutdown(SSL *a);
int q_SSL_set_session(SSL *to, SSL_SESSION *session);
void q_SSL_SESSION_free(SSL_SESSION *ses);
SSL_SESSION *q_SSL_get1_session(SSL *ssl);
SSL_SESSION *q_SSL_get_session(const SSL *ssl);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
int q_SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int q_SSL_set_ex_data(SSL *ssl, int idx, void *arg);
void *q_SSL_get_ex_data(const SSL *ssl, int idx);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
typedef unsigned int (*q_psk_client_callback_t)(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
void q_SSL_set_psk_client_callback(SSL *ssl, q_psk_client_callback_t callback);
typedef unsigned int (*q_psk_server_callback_t)(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);
void q_SSL_set_psk_server_callback(SSL *ssl, q_psk_server_callback_t callback);
int q_SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *hint);
#endif // OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#ifndef OPENSSL_NO_SSL2
const SSL_METHOD *q_SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
const SSL_METHOD *q_SSLv3_client_method();
#endif
const SSL_METHOD *q_SSLv23_client_method();
const SSL_METHOD *q_TLSv1_client_method();
const SSL_METHOD *q_TLSv1_1_client_method();
const SSL_METHOD *q_TLSv1_2_client_method();
#ifndef OPENSSL_NO_SSL2
const SSL_METHOD *q_SSLv2_server_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
const SSL_METHOD *q_SSLv3_server_method();
#endif
const SSL_METHOD *q_SSLv23_server_method();
const SSL_METHOD *q_TLSv1_server_method();
const SSL_METHOD *q_TLSv1_1_server_method();
const SSL_METHOD *q_TLSv1_2_server_method();
#else
#ifndef OPENSSL_NO_SSL2
SSL_METHOD *q_SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
SSL_METHOD *q_SSLv3_client_method();
#endif
SSL_METHOD *q_SSLv23_client_method();
SSL_METHOD *q_TLSv1_client_method();
SSL_METHOD *q_TLSv1_1_client_method();
SSL_METHOD *q_TLSv1_2_client_method();
#ifndef OPENSSL_NO_SSL2
SSL_METHOD *q_SSLv2_server_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
SSL_METHOD *q_SSLv3_server_method();
#endif
SSL_METHOD *q_SSLv23_server_method();
SSL_METHOD *q_TLSv1_server_method();
SSL_METHOD *q_TLSv1_1_server_method();
SSL_METHOD *q_TLSv1_2_server_method();
#endif
int q_SSL_write(SSL *a, const void *b, int c);
int q_X509_cmp(X509 *a, X509 *b);
#ifdef SSLEAY_MACROS
void *q_ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, char *x);
#define q_X509_dup(x509) (X509 *)q_ASN1_dup((i2d_of_void *)q_i2d_X509, \
                (d2i_of_void *)q_d2i_X509,(char *)x509)
#else
X509 *q_X509_dup(X509 *a);
#endif
void q_X509_print(BIO *a, X509*b);
ASN1_OBJECT *q_X509_EXTENSION_get_object(X509_EXTENSION *a);
void q_X509_free(X509 *a);
X509_EXTENSION *q_X509_get_ext(X509 *a, int b);
int q_X509_get_ext_count(X509 *a);
void *q_X509_get_ext_d2i(X509 *a, int b, int *c, int *d);
int q_ASN1_INTEGER_set(ASN1_INTEGER *a, long b);
BIGNUM *q_ASN1_INTEGER_to_BN(const ASN1_INTEGER *a, BIGNUM *b);
void q_ASN1_OBJECT_free(ASN1_OBJECT *a);
void q_ASN1_STRING_free(ASN1_STRING *a);
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
const unsigned char *q_ASN1_STRING_get0_data(const ASN1_STRING *a);
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL
ASN1_STRING *q_ASN1_STRING_type_new(int a);
char *q_BN_bn2dec(const BIGNUM *a);
int q_BN_dec2bn(BIGNUM **a, const char *b);
int q_BN_hex2bn(BIGNUM **a, char *b);
void q_BN_free(BIGNUM *a);
BIGNUM *q_BN_new();
int q_BN_set_word(BIGNUM *a, unsigned long b);
ASN1_INTEGER *q_BN_to_ASN1_INTEGER(BIGNUM *a, ASN1_INTEGER *b);
X509_CRL *q_d2i_X509_CRL(X509_CRL **a, const unsigned char **b, long c);
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
int q_DSA_bits(DSA *a);
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL
int q_DSA_generate_key(DSA *a);
int q_DSA_generate_parameters_ex(DSA *a, int b, const unsigned char *c, int d, int *e, unsigned long *f, BN_GENCB *g);
#ifndef OPENSSL_NO_EC
EC_GROUP *q_EC_GROUP_new(const EC_METHOD *a);
int q_EC_KEY_generate_key(EC_KEY *a);
const EC_METHOD *q_EC_GFp_mont_method();
EC_KEY *q_EC_KEY_new();
#endif // OPENSSL_NO_EC
int q_EVP_DigestSignInit(EVP_MD_CTX *a, EVP_PKEY_CTX **b, const EVP_MD *c, ENGINE *d, EVP_PKEY *e);
int q_EVP_MD_CTX_cleanup(EVP_MD_CTX *a);
void q_EVP_MD_CTX_init(EVP_MD_CTX *a);
#ifndef OPENSSL_NO_MD2
const EVP_MD *q_EVP_md2();
#else
inline const EVP_MD *q_EVP_md2(){return 0;}
#endif
#ifndef OPENSSL_NO_MD4
const EVP_MD *q_EVP_md4();
#else
inline const EVP_MD *q_EVP_md4(){return 0;}
#endif
#ifndef OPENSSL_NO_MD5
const EVP_MD *q_EVP_md5();
#else
inline const EVP_MD *q_EVP_md5(){return 0;}
#endif
#ifndef OPENSSL_NO_SHA
const EVP_MD *q_EVP_sha();
const EVP_MD *q_EVP_sha1();
const EVP_MD *q_EVP_dss1();
#else
inline const EVP_MD *q_EVP_sha(){return 0;}
inline const EVP_MD *q_EVP_sha1(){return 0;}
inline const EVP_MD *q_EVP_dss1(){return 0;}
#endif
#ifndef OPENSSL_NO_SHA256
const EVP_MD *q_EVP_sha224();
const EVP_MD *q_EVP_sha256();
#else
inline const EVP_MD *q_EVP_sha224(){return 0;}
inline const EVP_MD *q_EVP_sha224(){return 0;}
#endif
#ifndef OPENSSL_NO_SHA512
const EVP_MD *q_EVP_sha384();
const EVP_MD *q_EVP_sha512();
#else
inline const EVP_MD *q_EVP_sha384(){return 0;}
inline const EVP_MD *q_EVP_sha512(){return 0;}
#endif
#ifndef OPENSSL_NO_MDC2
const EVP_MD *q_EVP_mdc2();
#else
inline const EVP_MD *q_EVP_mdc2(){return 0;}
#endif
#ifndef OPENSSL_NO_RIPEMD
const EVP_MD *q_EVP_ripemd160();
#else
inline const EVP_MD *q_EVP_ripemd160(){return 0;}
#endif
#ifndef OPENSSL_NO_DES
const EVP_CIPHER *q_EVP_des_ecb();
const EVP_CIPHER *q_EVP_des_ede();
const EVP_CIPHER *q_EVP_des_ede3();
const EVP_CIPHER *q_EVP_des_ede_ecb();
const EVP_CIPHER *q_EVP_des_ede3_ecb();
const EVP_CIPHER *q_EVP_des_cfb64();
const EVP_CIPHER *q_EVP_des_cfb1();
const EVP_CIPHER *q_EVP_des_cfb8();
const EVP_CIPHER *q_EVP_des_ede_cfb64();
const EVP_CIPHER *q_EVP_des_ede3_cfb64();
const EVP_CIPHER *q_EVP_des_ede3_cfb1();
const EVP_CIPHER *q_EVP_des_ede3_cfb8();
const EVP_CIPHER *q_EVP_des_ofb();
const EVP_CIPHER *q_EVP_des_ede_ofb();
const EVP_CIPHER *q_EVP_des_ede3_ofb();
const EVP_CIPHER *q_EVP_des_cbc();
const EVP_CIPHER *q_EVP_des_ede_cbc();
const EVP_CIPHER *q_EVP_des_ede3_cbc();
const EVP_CIPHER *q_EVP_desx_cbc();
#else
inline const EVP_CIPHER *q_EVP_des_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede3(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede3_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_des_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_des_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_des_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede3_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede3_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede3_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede3_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_des_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_des_ede3_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_desx_cbc(){return 0;}
#endif // OPENSSL_NO_DES
#ifndef OPENSSL_NO_RC4
const EVP_CIPHER *q_EVP_rc4();
const EVP_CIPHER *q_EVP_rc4_40();
#ifndef OPENSSL_NO_MD5
const EVP_CIPHER *q_EVP_rc4_hmac_md5();
#else
inline const EVP_CIPHER *q_EVP_rc4_hmac_md5(){return 0;}
#endif // OPENSSL_NO_MD5
#else
inline const EVP_CIPHER *q_EVP_rc4(){return 0;}
inline const EVP_CIPHER *q_EVP_rc4_40(){return 0;}
#endif // OPENSSL_NO_RC4
#ifndef OPENSSL_NO_IDEA
const EVP_CIPHER *q_EVP_idea_ecb();
const EVP_CIPHER *q_EVP_idea_cfb64();
const EVP_CIPHER *q_EVP_idea_ofb();
const EVP_CIPHER *q_EVP_idea_cbc();
#else
inline const EVP_CIPHER *q_EVP_idea_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_idea_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_idea_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_idea_cbc(){return 0;}
#endif // OPENSSL_NO_IDEA
#ifndef OPENSSL_NO_RC2
const EVP_CIPHER *q_EVP_rc2_ecb();
const EVP_CIPHER *q_EVP_rc2_cbc();
const EVP_CIPHER *q_EVP_rc2_40_cbc();
const EVP_CIPHER *q_EVP_rc2_64_cbc();
const EVP_CIPHER *q_EVP_rc2_cfb64();
const EVP_CIPHER *q_EVP_rc2_ofb();
#else
inline const EVP_CIPHER *q_EVP_rc2_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_rc2_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_rc2_40_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_rc2_64_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_rc2_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_rc2_ofb(){return 0;}
#endif // OPENSSL_NO_RC2
#ifndef OPENSSL_NO_BF
const EVP_CIPHER *q_EVP_bf_ecb();
const EVP_CIPHER *q_EVP_bf_cbc();
const EVP_CIPHER *q_EVP_bf_cfb64();
const EVP_CIPHER *q_EVP_bf_ofb();
#else
inline const EVP_CIPHER *q_EVP_bf_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_bf_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_bf_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_bf_ofb(){return 0;}
#endif // OPENSSL_NO_BF
#ifndef OPENSSL_NO_CAST
const EVP_CIPHER *q_EVP_cast5_ecb();
const EVP_CIPHER *q_EVP_cast5_cbc();
const EVP_CIPHER *q_EVP_cast5_cfb64();
const EVP_CIPHER *q_EVP_cast5_ofb();
#else
inline const EVP_CIPHER *q_EVP_cast5_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_cast5_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_cast5_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_cast5_ofb(){return 0;}
#endif // OPENSSL_NO_CAST
#ifndef OPENSSL_NO_RC5
const EVP_CIPHER *q_EVP_rc5_32_12_16_cbc();
const EVP_CIPHER *q_EVP_rc5_32_12_16_ecb();
const EVP_CIPHER *q_EVP_rc5_32_12_16_cfb64();
const EVP_CIPHER *q_EVP_rc5_32_12_16_ofb();
#else
inline const EVP_CIPHER *q_EVP_rc5_32_12_16_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_rc5_32_12_16_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_rc5_32_12_16_cfb64(){return 0;}
inline const EVP_CIPHER *q_EVP_rc5_32_12_16_ofb(){return 0;}
#endif // OPENSSL_NO_RC5
#ifndef OPENSSL_NO_AES
const EVP_CIPHER *q_EVP_aes_128_ecb();
const EVP_CIPHER *q_EVP_aes_128_cbc();
const EVP_CIPHER *q_EVP_aes_128_cfb1();
const EVP_CIPHER *q_EVP_aes_128_cfb8();
const EVP_CIPHER *q_EVP_aes_128_cfb128();
const EVP_CIPHER *q_EVP_aes_128_ofb();
const EVP_CIPHER *q_EVP_aes_128_ctr();
const EVP_CIPHER *q_EVP_aes_128_ccm();
const EVP_CIPHER *q_EVP_aes_128_gcm();
const EVP_CIPHER *q_EVP_aes_128_xts();
const EVP_CIPHER *q_EVP_aes_192_ecb();
const EVP_CIPHER *q_EVP_aes_192_cbc();
const EVP_CIPHER *q_EVP_aes_192_cfb1();
const EVP_CIPHER *q_EVP_aes_192_cfb8();
const EVP_CIPHER *q_EVP_aes_192_cfb128();
const EVP_CIPHER *q_EVP_aes_192_ofb();
const EVP_CIPHER *q_EVP_aes_192_ctr();
const EVP_CIPHER *q_EVP_aes_192_ccm();
const EVP_CIPHER *q_EVP_aes_192_gcm();
const EVP_CIPHER *q_EVP_aes_256_ecb();
const EVP_CIPHER *q_EVP_aes_256_cbc();
const EVP_CIPHER *q_EVP_aes_256_cfb1();
const EVP_CIPHER *q_EVP_aes_256_cfb8();
const EVP_CIPHER *q_EVP_aes_256_cfb128();
const EVP_CIPHER *q_EVP_aes_256_ofb();
const EVP_CIPHER *q_EVP_aes_256_ctr();
const EVP_CIPHER *q_EVP_aes_256_ccm();
const EVP_CIPHER *q_EVP_aes_256_gcm();
const EVP_CIPHER *q_EVP_aes_256_xts();
#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
const EVP_CIPHER *q_EVP_aes_128_cbc_hmac_sha1();
const EVP_CIPHER *q_EVP_aes_256_cbc_hmac_sha1();
#else
inline const EVP_CIPHER *q_EVP_aes_128_cbc_hmac_sha1(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_cbc_hmac_sha1(){return 0;}
#endif // !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
#ifndef OPENSSL_NO_SHA256
const EVP_CIPHER *q_EVP_aes_128_cbc_hmac_sha256();
const EVP_CIPHER *q_EVP_aes_256_cbc_hmac_sha256();
#else
inline const EVP_CIPHER *q_EVP_aes_128_cbc_hmac_sha256(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_cbc_hmac_sha256(){return 0;}
#endif // OPENSSL_NO_SHA256
#else
inline const EVP_CIPHER *q_EVP_aes_128_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_cfb128(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_ctr(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_ccm(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_gcm(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_128_xts(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_cfb128(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_ctr(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_ccm(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_192_gcm(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_cfb128(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_ctr(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_ccm(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_gcm(){return 0;}
inline const EVP_CIPHER *q_EVP_aes_256_xts(){return 0;}
#endif // OPENSSL_NO_AES
#ifndef OPENSSL_NO_CAMELLIA
const EVP_CIPHER *q_EVP_camellia_128_ecb();
const EVP_CIPHER *q_EVP_camellia_128_cbc();
const EVP_CIPHER *q_EVP_camellia_128_cfb1();
const EVP_CIPHER *q_EVP_camellia_128_cfb8();
const EVP_CIPHER *q_EVP_camellia_128_cfb128();
const EVP_CIPHER *q_EVP_camellia_128_ofb();
const EVP_CIPHER *q_EVP_camellia_192_ecb();
const EVP_CIPHER *q_EVP_camellia_192_cbc();
const EVP_CIPHER *q_EVP_camellia_192_cfb1();
const EVP_CIPHER *q_EVP_camellia_192_cfb8();
const EVP_CIPHER *q_EVP_camellia_192_cfb128();
const EVP_CIPHER *q_EVP_camellia_192_ofb();
const EVP_CIPHER *q_EVP_camellia_256_ecb();
const EVP_CIPHER *q_EVP_camellia_256_cbc();
const EVP_CIPHER *q_EVP_camellia_256_cfb1();
const EVP_CIPHER *q_EVP_camellia_256_cfb8();
const EVP_CIPHER *q_EVP_camellia_256_cfb128();
const EVP_CIPHER *q_EVP_camellia_256_ofb();
#else
inline const EVP_CIPHER *q_EVP_camellia_128_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_128_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_128_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_128_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_128_cfb128(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_128_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_192_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_192_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_192_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_192_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_192_cfb128(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_192_ofb(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_256_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_256_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_256_cfb1(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_256_cfb8(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_256_cfb128(){return 0;}
inline const EVP_CIPHER *q_EVP_camellia_256_ofb(){return 0;}
#endif // OPENSSL_NO_CAMELLIA
#ifndef OPENSSL_NO_SEED
const EVP_CIPHER *q_EVP_seed_ecb();
const EVP_CIPHER *q_EVP_seed_cbc();
const EVP_CIPHER *q_EVP_seed_cfb128();
const EVP_CIPHER *q_EVP_seed_ofb();
#else
inline const EVP_CIPHER *q_EVP_seed_ecb(){return 0;}
inline const EVP_CIPHER *q_EVP_seed_cbc(){return 0;}
inline const EVP_CIPHER *q_EVP_seed_cfb128(){return 0;}
inline const EVP_CIPHER *q_EVP_seed_ofb(){return 0;}
#endif // OPENSSL_NO_SEED
int q_i2d_X509_CRL(X509_CRL *a, unsigned char **b);
int q_PEM_write_bio_X509_CRL(BIO *a, X509_CRL *b);
int q_PEM_write_X509_CRL(FILE *a, X509_CRL *b);
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
int q_RSA_bits(RSA *a);
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL
int q_RSA_generate_key_ex(RSA *a, int b, BIGNUM *c, BN_GENCB *d);
int q_X509_add_ext(X509 *a, X509_EXTENSION *b, int c);
void q_X509_ALGOR_free(X509_ALGOR *a);
X509_ALGOR *q_X509_ALGOR_new();
void q_X509_ALGOR_get0(ASN1_OBJECT **a, int *b, void **c, X509_ALGOR *d);
int q_X509_check_private_key(X509 *a, EVP_PKEY *b);
int q_X509_CRL_add1_ext_i2d(X509_CRL *a, int b, void *c, int d, unsigned long e);
void q_X509_CRL_free(X509_CRL *a);
int q_X509_CRL_add_ext(X509_CRL *a, X509_EXTENSION *b, int c);
int q_X509_CRL_add0_revoked(X509_CRL *a, X509_REVOKED *b);
X509_CRL *q_X509_CRL_dup(X509_CRL *a);
X509_EXTENSION *q_X509_CRL_get_ext(X509_CRL *a, int b);
int q_X509_CRL_get_ext_count(X509_CRL *a);
void *q_X509_CRL_get_ext_d2i(X509_CRL *a, int b, int *c, int *d);
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
X509_NAME *q_X509_CRL_get_issuer(const X509_CRL *a);
const ASN1_TIME *q_X509_CRL_get0_lastUpdate(const X509_CRL *a);
const ASN1_TIME *q_X509_CRL_get0_nextUpdate(const X509_CRL *a);
STACK_OF(X509_REVOKED) *q_X509_CRL_get_REVOKED(X509_CRL *a);
void q_X509_CRL_get0_signature(const X509_CRL *a, const ASN1_BIT_STRING **b, const X509_ALGOR **c);
#else
#define q_X509_CRL_get_issuer(x) X509_CRL_get_issuer(x)
#define q_X509_CRL_get_lastUpdate(x) X509_CRL_get_lastUpdate(x)
#define q_X509_CRL_get_nextUpdate(x) X509_CRL_get_nextUpdate(x)
#define q_X509_CRL_get_REVOKED(x) X509_CRL_get_REVOKED(x)
#define q_X509_CRL_get_version(x) X509_CRL_get_version(x)
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL
int q_X509_CRL_match(const X509_CRL *a, const X509_CRL *b);
X509_CRL *q_X509_CRL_new();
int q_X509_CRL_set_issuer_name(X509_CRL *a, X509_NAME *b);
int q_X509_CRL_set_lastUpdate(X509_CRL *a, const ASN1_TIME *b);
int q_X509_CRL_set_nextUpdate(X509_CRL *a, const ASN1_TIME *b);
int q_X509_CRL_print(BIO *a, X509_CRL *b);
int q_X509_CRL_set_version(X509_CRL *a, long b);
int q_X509_CRL_sign_ctx(X509_CRL *a, EVP_MD_CTX *b);
int q_X509_CRL_sort(X509_CRL *a);
int q_X509_CRL_verify(X509_CRL *a, EVP_PKEY *b);
void q_X509_EXTENSION_free(X509_EXTENSION *a);
EVP_PKEY *q_X509_get_pubkey(X509 *a);
ASN1_TIME *q_X509_gmtime_adj(ASN1_TIME *a, long b);
int q_X509_NAME_add_entry_by_txt(X509_NAME *a, const char *b, int c, const unsigned char *d, int e, int f, int g);
void q_X509_NAME_free(X509_NAME *a);
X509 *q_X509_new();
void q_X509_OBJECT_free_contents(X509_OBJECT *a);
X509_REVOKED *q_X509_REVOKED_new();
int q_X509_REVOKED_set_revocationDate(X509_REVOKED *a, ASN1_TIME *b);
int q_X509_REVOKED_set_serialNumber(X509_REVOKED *a, ASN1_INTEGER *b);
int q_X509_set_issuer_name(X509 *a, X509_NAME *b);
int q_X509_set_pubkey(X509 *a, EVP_PKEY *b);
int q_X509_set_serialNumber(X509 *a, ASN1_INTEGER *b);
int q_X509_set_subject_name(X509 *a, X509_NAME *b);
int q_X509_set_version(X509 *a, long b);
int q_X509_sign(X509 *a, EVP_PKEY *b, const EVP_MD *c);
int q_X509_STORE_get_by_subject(X509_STORE_CTX *a, int b, X509_NAME *c, X509_OBJECT *d);
ASN1_TIME *q_X509_time_adj_ex(ASN1_TIME *a, int b, long c, time_t *d);
int q_X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **a, int b, void *c, int d, unsigned long e);
X509_EXTENSION *q_X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *a, X509V3_CTX *b, int c, char *d);
X509_EXTENSION *q_X509v3_get_ext(const STACK_OF(X509_EXTENSION) *a, int b);
int q_X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *a);
void q_X509V3_set_ctx(X509V3_CTX *a, X509 *b, X509 *c, X509_REQ *d, X509_CRL *e, int f);
const X509V3_EXT_METHOD *q_X509V3_EXT_get(X509_EXTENSION *a);
void *q_X509V3_EXT_d2i(X509_EXTENSION *a);
int q_X509_EXTENSION_get_critical(X509_EXTENSION *a);
ASN1_OCTET_STRING *q_X509_EXTENSION_get_data(X509_EXTENSION *a);
void q_BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);
void q_AUTHORITY_KEYID_free(AUTHORITY_KEYID *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
int q_ASN1_STRING_print(BIO *a, const ASN1_STRING *b);
#else
int q_ASN1_STRING_print(BIO *a, ASN1_STRING *b);
#endif
int q_X509_check_issued(X509 *a, X509 *b);
X509_NAME *q_X509_get_issuer_name(X509 *a);
X509_NAME *q_X509_get_subject_name(X509 *a);
int q_X509_verify_cert(X509_STORE_CTX *ctx);
int q_X509_NAME_entry_count(X509_NAME *a);
X509_NAME_ENTRY *q_X509_NAME_get_entry(X509_NAME *a,int b);
ASN1_STRING *q_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *a);
ASN1_OBJECT *q_X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *a);
EVP_PKEY *q_X509_PUBKEY_get(X509_PUBKEY *a);
void q_X509_STORE_free(X509_STORE *store);
X509_STORE *q_X509_STORE_new();
int q_X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
void q_X509_STORE_CTX_free(X509_STORE_CTX *storeCtx);
int q_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
                          X509 *x509, STACK_OF(X509) *chain);
X509_STORE_CTX *q_X509_STORE_CTX_new();
int q_X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int q_X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
int q_X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509 *q_X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
STACK_OF(X509) *q_X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);

// Diffie-Hellman support
DH *q_DH_new();
void q_DH_free(DH *dh);
DH *q_d2i_DHparams(DH **a, const unsigned char **pp, long length);
int q_i2d_DHparams(DH *a, unsigned char **p);
int q_DH_check(DH *dh, int *codes);

BIGNUM *q_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
#define q_SSL_CTX_set_tmp_dh(ctx, dh) q_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_TMP_DH, 0, (char *)dh)

#ifndef OPENSSL_NO_EC
// EC Diffie-Hellman support
EC_KEY *q_EC_KEY_dup(const EC_KEY *src);
EC_KEY *q_EC_KEY_new_by_curve_name(int nid);
void q_EC_KEY_free(EC_KEY *ecdh);
#define q_SSL_CTX_set_tmp_ecdh(ctx, ecdh) q_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_TMP_ECDH, 0, (char *)ecdh)

// EC curves management
size_t q_EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
int q_EC_curve_nist2nid(const char *name);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
#endif // OPENSSL_NO_EC
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define q_SSL_get_server_tmp_key(ssl, key) q_SSL_ctrl((ssl), SSL_CTRL_GET_SERVER_TMP_KEY, 0, (char *)key)
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

// PKCS#12 support
int q_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
PKCS12 *q_d2i_PKCS12_bio(BIO *bio, PKCS12 **pkcs12);
void q_PKCS12_free(PKCS12 *pkcs12);


#define q_BIO_get_mem_data(b, pp) (int)q_BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)pp)
#define q_BIO_pending(b) (int)q_BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)
#ifdef SSLEAY_MACROS
int     q_i2d_DSAPrivateKey(const DSA *a, unsigned char **pp);
int     q_i2d_RSAPrivateKey(const RSA *a, unsigned char **pp);
RSA *q_d2i_RSAPrivateKey(RSA **a, unsigned char **pp, long length);
DSA *q_d2i_DSAPrivateKey(DSA **a, unsigned char **pp, long length);
#define q_PEM_read_bio_RSAPrivateKey(bp, x, cb, u) \
        (RSA *)q_PEM_ASN1_read_bio( \
        (void *(*)(void**, const unsigned char**, long int))q_d2i_RSAPrivateKey, PEM_STRING_RSA, bp, (void **)x, cb, u)
#define q_PEM_read_bio_DSAPrivateKey(bp, x, cb, u) \
        (DSA *)q_PEM_ASN1_read_bio( \
        (void *(*)(void**, const unsigned char**, long int))q_d2i_DSAPrivateKey, PEM_STRING_DSA, bp, (void **)x, cb, u)
#define q_PEM_write_bio_RSAPrivateKey(bp,x,enc,kstr,klen,cb,u) \
        PEM_ASN1_write_bio((int (*)(void*, unsigned char**))q_i2d_RSAPrivateKey,PEM_STRING_RSA,\
                           bp,(char *)x,enc,kstr,klen,cb,u)
#define q_PEM_write_bio_DSAPrivateKey(bp,x,enc,kstr,klen,cb,u) \
        PEM_ASN1_write_bio((int (*)(void*, unsigned char**))q_i2d_DSAPrivateKey,PEM_STRING_DSA,\
                           bp,(char *)x,enc,kstr,klen,cb,u)
#define q_PEM_read_bio_DHparams(bp, dh, cb, u) \
        (DH *)q_PEM_ASN1_read_bio( \
        (void *(*)(void**, const unsigned char**, long int))q_d2i_DHparams, PEM_STRING_DHPARAMS, bp, (void **)x, cb, u)
#endif
#define q_SSL_CTX_set_options(ctx,op) q_SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,(op),NULL)
#define q_SSL_CTX_set_mode(ctx,op) q_SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)
#define q_SKM_sk_num(type, st) ((int (*)(const STACK_OF(type) *))q_sk_num)(st)
#define q_SKM_sk_value(type, st,i) ((type * (*)(const STACK_OF(type) *, int))q_sk_value)(st, i)
#define q_sk_GENERAL_NAME_num(st) q_SKM_sk_num(GENERAL_NAME, (st))
#define q_sk_GENERAL_NAME_value(st, i) q_SKM_sk_value(GENERAL_NAME, (st), (i))
#define q_sk_X509_num(st) q_SKM_sk_num(X509, (st))
#define q_sk_X509_value(st, i) q_SKM_sk_value(X509, (st), (i))
#define q_sk_SSL_CIPHER_num(st) q_SKM_sk_num(SSL_CIPHER, (st))
#define q_sk_SSL_CIPHER_value(st, i) q_SKM_sk_value(SSL_CIPHER, (st), (i))
#define q_SSL_CTX_add_extra_chain_cert(ctx,x509) \
        q_SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)x509)
#define q_X509_get_notAfter(x) X509_get_notAfter(x)
#define q_X509_get_notBefore(x) X509_get_notBefore(x)
#define q_EVP_PKEY_assign_RSA(pkey,rsa) q_EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                        (char *)(rsa))
#define q_EVP_PKEY_assign_DSA(pkey,dsa) q_EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                        (char *)(dsa))
#define q_OpenSSL_add_all_algorithms() q_OPENSSL_add_all_algorithms_conf()
char *q_CONF_get1_default_config_file();
void q_OPENSSL_add_all_algorithms_noconf();
void q_OPENSSL_add_all_algorithms_conf();
int q_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
long q_SSLeay();
const char *q_SSLeay_version(int type);
int q_i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp);
SSL_SESSION *q_d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length);

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)
int q_SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
                            const unsigned char *in, unsigned int inlen,
                            const unsigned char *client, unsigned int client_len);
void q_SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
                                        int (*cb) (SSL *ssl, unsigned char **out,
                                                   unsigned char *outlen,
                                                   const unsigned char *in,
                                                   unsigned int inlen, void *arg),
                                        void *arg);
void q_SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
                                      unsigned *len);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
int q_SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos,
                          unsigned protos_len);
void q_SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                  int (*cb) (SSL *ssl,
                                             const unsigned char **out,
                                             unsigned char *outlen,
                                             const unsigned char *in,
                                             unsigned int inlen,
                                             void *arg), void *arg);
void q_SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
                              unsigned *len);
#endif
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...

// Helper function
class QDateTime;
QDateTime q_getTimeFromASN1(const ASN1_TIME *aTime);

QT_END_NAMESPACE

#endif

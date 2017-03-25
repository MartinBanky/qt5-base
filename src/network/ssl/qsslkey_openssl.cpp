/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
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


#include "qsslkey.h"
#include "qsslkey_p.h"
#include "qsslsocket_openssl_symbols_p.h"
#include "qsslsocket.h"
#include "qsslsocket_p.h"

#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qiodevice.h>
#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

QT_BEGIN_NAMESPACE

void QSslKeyPrivate::clear(bool deep)
{
    isNull = true;
    if (!QSslSocket::supportsSsl())
        return;

    if (pKey) {
        if (deep) {
            q_EVP_PKEY_free(pKey);
        }

        pKey = 0;
    }
}

/*!
    \internal

    Creates an array of function pointers and uses the QSslKey::Cipher
    as the index to get the pointer to the correct cipher structure.
 */
const EVP_CIPHER *QSslKeyPrivate::getCipherStructure() const
{
    CipherType cipherType[] = {
        q_EVP_des_ecb,
        q_EVP_des_ede,
        q_EVP_des_ede3,
        q_EVP_des_ede_ecb,
        q_EVP_des_ede3_ecb,
        q_EVP_des_cfb64,
        q_EVP_des_cfb1,
        q_EVP_des_cfb8,
        q_EVP_des_ede_cfb64,
        q_EVP_des_ede3_cfb64,
        q_EVP_des_ede3_cfb1,
        q_EVP_des_ede3_cfb8,
        q_EVP_des_ofb,
        q_EVP_des_ede_ofb,
        q_EVP_des_ede3_ofb,
        q_EVP_des_cbc,
        q_EVP_des_ede_cbc,
        q_EVP_des_ede3_cbc,
        q_EVP_desx_cbc,
        q_EVP_rc4,
        q_EVP_rc4_40,
        q_EVP_rc4_hmac_md5,
        q_EVP_idea_ecb,
        q_EVP_idea_cfb64,
        q_EVP_idea_ofb,
        q_EVP_idea_cbc,
        q_EVP_rc2_ecb,
        q_EVP_rc2_cbc,
        q_EVP_rc2_40_cbc,
        q_EVP_rc2_64_cbc,
        q_EVP_rc2_cfb64,
        q_EVP_rc2_ofb,
        q_EVP_bf_ecb,
        q_EVP_bf_cbc,
        q_EVP_bf_cfb64,
        q_EVP_bf_ofb,
        q_EVP_cast5_ecb,
        q_EVP_cast5_cbc,
        q_EVP_cast5_cfb64,
        q_EVP_cast5_ofb,
        q_EVP_rc5_32_12_16_cbc,
        q_EVP_rc5_32_12_16_ecb,
        q_EVP_rc5_32_12_16_cfb64,
        q_EVP_rc5_32_12_16_ofb,
        q_EVP_aes_128_ecb,
        q_EVP_aes_128_cbc,
        q_EVP_aes_128_cfb1,
        q_EVP_aes_128_cfb8,
        q_EVP_aes_128_cfb128,
        q_EVP_aes_128_ofb,
        q_EVP_aes_128_ctr,
        q_EVP_aes_128_ccm,
        q_EVP_aes_128_gcm,
        q_EVP_aes_128_xts,
        q_EVP_aes_192_ecb,
        q_EVP_aes_192_cbc,
        q_EVP_aes_192_cfb1,
        q_EVP_aes_192_cfb8,
        q_EVP_aes_192_cfb128,
        q_EVP_aes_192_ofb,
        q_EVP_aes_192_ctr,
        q_EVP_aes_192_ccm,
        q_EVP_aes_192_gcm,
        q_EVP_aes_256_ecb,
        q_EVP_aes_256_cbc,
        q_EVP_aes_256_cfb1,
        q_EVP_aes_256_cfb8,
        q_EVP_aes_256_cfb128,
        q_EVP_aes_256_ofb,
        q_EVP_aes_256_ctr,
        q_EVP_aes_256_ccm,
        q_EVP_aes_256_gcm,
        q_EVP_aes_256_xts,
        q_EVP_aes_128_cbc_hmac_sha1,
        q_EVP_aes_256_cbc_hmac_sha1,
        q_EVP_aes_128_cbc_hmac_sha256,
        q_EVP_aes_256_cbc_hmac_sha256,
        q_EVP_camellia_128_ecb,
        q_EVP_camellia_128_cbc,
        q_EVP_camellia_128_cfb1,
        q_EVP_camellia_128_cfb8,
        q_EVP_camellia_128_cfb128,
        q_EVP_camellia_128_ofb,
        q_EVP_camellia_192_ecb,
        q_EVP_camellia_192_cbc,
        q_EVP_camellia_192_cfb1,
        q_EVP_camellia_192_cfb8,
        q_EVP_camellia_192_cfb128,
        q_EVP_camellia_192_ofb,
        q_EVP_camellia_256_ecb,
        q_EVP_camellia_256_cbc,
        q_EVP_camellia_256_cfb1,
        q_EVP_camellia_256_cfb8,
        q_EVP_camellia_256_cfb128,
        q_EVP_camellia_256_ofb,
        q_EVP_seed_ecb,
        q_EVP_seed_cbc,
        q_EVP_seed_cfb128,
        q_EVP_seed_ofb,
    };

    return cipherType[this->cipher]();
}

bool QSslKeyPrivate::fromEVP_PKEY(EVP_PKEY *pkey)
{
    q_EVP_PKEY_free(pKey);
    pKey = q_EVP_PKEY_new();

    *pKey = *pkey;

    if (pkey->type == EVP_PKEY_RSA) {
        isNull = false;
        algorithm = QSsl::Rsa;
        type = QSsl::PrivateKey;

        return true;
    }
    else if (pkey->type == EVP_PKEY_DSA) {
        isNull = false;
        algorithm = QSsl::Dsa;
        type = QSsl::PrivateKey;

        return true;
    }
#ifndef OPENSSL_NO_EC
    else if (pkey->type == EVP_PKEY_EC) {
        isNull = false;
        algorithm = QSsl::Ec;
        type = QSsl::PrivateKey;

        return true;
    }
#endif
    else {
        // Unknown key type. This could be handled as opaque, but then
        // we'd eventually leak memory since we wouldn't be able to free
        // the underlying EVP_PKEY structure. For now, we won't support
        // this.
    }

    return false;
}

void QSslKeyPrivate::decodeDer(const QByteArray &der, bool deepClear)
{
    QMap<QByteArray, QByteArray> headers;
    decodePem(pemFromDer(der, headers), QByteArray(), deepClear);
}

void QSslKeyPrivate::decodePem(const QByteArray &pem, const QByteArray &passPhrase,
                               bool deepClear)
{
    if (pem.isEmpty())
        return;

    clear(deepClear);

    if (!QSslSocket::supportsSsl())
        return;

    BIO *bio = q_BIO_new_mem_buf(const_cast<char *>(pem.data()), pem.size());
    if (!bio)
        return;

    void *phrase = const_cast<char *>(passPhrase.constData());

    q_EVP_PKEY_free(pKey);
    pKey = q_EVP_PKEY_new();

    if (algorithm == QSsl::Rsa) {
        RSA *result = (type == QSsl::PublicKey)
            ? q_PEM_read_bio_RSA_PUBKEY(bio, &pKey->pkey.rsa, 0, phrase)
            : q_PEM_read_bio_RSAPrivateKey(bio, &pKey->pkey.rsa, 0, phrase);
        if (pKey->pkey.rsa && pKey->pkey.rsa == result) {
            isNull = false;
            q_EVP_PKEY_assign(pKey, EVP_PKEY_RSA, pKey->pkey.rsa);
        }
    } else if (algorithm == QSsl::Dsa) {
        DSA *result = (type == QSsl::PublicKey)
            ? q_PEM_read_bio_DSA_PUBKEY(bio, &pKey->pkey.dsa, 0, phrase)
            : q_PEM_read_bio_DSAPrivateKey(bio, &pKey->pkey.dsa, 0, phrase);
        if (pKey->pkey.dsa && pKey->pkey.dsa == result) {
            isNull = false;
            q_EVP_PKEY_assign(pKey, EVP_PKEY_DSA, pKey->pkey.dsa);
        }
#ifndef OPENSSL_NO_EC
    } else if (algorithm == QSsl::Ec) {
        EC_KEY *result = (type == QSsl::PublicKey)
            ? q_PEM_read_bio_EC_PUBKEY(bio, &pKey->pkey.ec, 0, phrase)
            : q_PEM_read_bio_ECPrivateKey(bio, &pKey->pkey.ec, 0, phrase);
        if (pKey->pkey.ec && pKey->pkey.ec == result) {
            isNull = false;
            q_EVP_PKEY_assign(pKey, EVP_PKEY_EC, pKey->pkey.ec);
        }
#endif
    }

    q_BIO_free(bio);
}

int QSslKeyPrivate::length() const
{
    if (isNull || algorithm == QSsl::Opaque)
        return -1;

    switch (algorithm) {
        case QSsl::Rsa: return q_BN_num_bits(pKey->pkey.rsa->n);
        case QSsl::Dsa: return q_BN_num_bits(pKey->pkey.dsa->p);
#ifndef OPENSSL_NO_EC
        case QSsl::Ec: return q_EC_GROUP_get_degree(q_EC_KEY_get0_group(pKey->pkey.ec));
#endif
        default: return -1;
    }
}

QByteArray QSslKeyPrivate::toPem(const QByteArray &passPhrase) const
{
    if (!QSslSocket::supportsSsl() || isNull || algorithm == QSsl::Opaque)
        return QByteArray();

    BIO *bio = q_BIO_new(q_BIO_s_mem());
    if (!bio)
        return QByteArray();

    const EVP_CIPHER *cipher = passPhrase.isEmpty() ? 0 : getCipherStructure();

    if (!passPhrase.isEmpty() && !cipher) {
        return QByteArray("Cipher is unavailable");
    }

    bool fail = false;

    if (algorithm == QSsl::Rsa) {
        if (type == QSsl::PublicKey) {
            if (!q_PEM_write_bio_RSA_PUBKEY(bio, pKey->pkey.rsa))
                fail = true;
        } else {
            if (!q_PEM_write_bio_RSAPrivateKey(
                    bio, pKey->pkey.rsa, cipher,
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
    } else if (algorithm == QSsl::Dsa) {
        if (type == QSsl::PublicKey) {
            if (!q_PEM_write_bio_DSA_PUBKEY(bio, pKey->pkey.dsa))
                fail = true;
        } else {
            if (!q_PEM_write_bio_DSAPrivateKey(
                    bio, pKey->pkey.dsa, cipher,
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
#ifndef OPENSSL_NO_EC
    } else if (algorithm == QSsl::Ec) {
        if (type == QSsl::PublicKey) {
            if (!q_PEM_write_bio_EC_PUBKEY(bio, pKey->pkey.ec))
                fail = true;
        } else {
            if (!q_PEM_write_bio_ECPrivateKey(
                    bio, pKey->pkey.ec, cipher,
                    const_cast<uchar *>((const uchar *)passPhrase.data()), passPhrase.size(), 0, 0)) {
                fail = true;
            }
        }
#endif
    } else {
        fail = true;
    }

    QByteArray pem;
    if (!fail) {
        char *data;
        long size = q_BIO_get_mem_data(bio, &data);
        pem = QByteArray(data, size);
    }
    q_BIO_free(bio);
    return pem;
}

Qt::HANDLE QSslKeyPrivate::handle() const
{
    switch (algorithm) {
    case QSsl::Opaque:
        return Qt::HANDLE(pKey);
    case QSsl::Rsa:
        return Qt::HANDLE(pKey->pkey.rsa);
    case QSsl::Dsa:
        return Qt::HANDLE(pKey->pkey.dsa);
#ifndef OPENSSL_NO_EC
    case QSsl::Ec:
        return Qt::HANDLE(pKey->pkey.ec);
#endif
    default:
        return Qt::HANDLE(NULL);
    }
}

void QSslKeyPrivate::generatePrivateKey()
{
    switch (algorithm) {
    case QSsl::Rsa: {
        q_EVP_PKEY_free(pKey);
        pKey = q_EVP_PKEY_new();

        q_RSA_free(pKey->pkey.rsa);
        pKey->pkey.rsa = q_RSA_new();

         BIGNUM *bigNum = q_BN_new();
         q_BN_set_word(bigNum, RSA_F4);

        q_RSA_generate_key_ex(pKey->pkey.rsa, bitSize, bigNum, 0);
        q_BN_free(bigNum);

        q_EVP_PKEY_assign(pKey, EVP_PKEY_RSA, pKey->pkey.rsa);
        isNull = false;
    }
    break;
    case QSsl::Dsa: {
        qsrand(static_cast<quint32>(QDateTime::currentDateTime().toSecsSinceEpoch()));

        QByteArray seed;

        do {
            seed.append(QByteArray::number(qrand(), 10));
        } while (seed.size() < 256);

        seed = seed.left(256);

        q_EVP_PKEY_free(pKey);
        pKey = q_EVP_PKEY_new();

        q_DSA_free(pKey->pkey.dsa);
        pKey->pkey.dsa = q_DSA_new();

        if (bitSize > 1024) {
            bitSize = 1024;
        }

        q_DSA_generate_parameters_ex(pKey->pkey.dsa, bitSize, reinterpret_cast<const uchar *>(seed.constData()), seed.size(), 0, 0, 0);
        q_DSA_generate_key(pKey->pkey.dsa);

        q_EVP_PKEY_assign(pKey, EVP_PKEY_DSA, pKey->pkey.dsa);
        isNull = false;
    }
    break;
    case QSsl::Ec:
    case QSsl::Opaque:
    default:
        break;
    }

//EVP_PKEY_encrypt
}

static QByteArray doCrypt(QSslKey::Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv, int enc)
{
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER* type = 0;
    int i = 0, len = 0;

    switch (cipher) {
    case QSslKey::DesCbc:
        type = q_EVP_des_cbc();
        break;
    case QSslKey::DesEde3Cbc:
        type = q_EVP_des_ede3_cbc();
        break;
    case QSslKey::Rc2Cbc:
        type = q_EVP_rc2_cbc();
        break;
    default:
        break;
    }

    QByteArray output;
    output.resize(data.size() + EVP_MAX_BLOCK_LENGTH);
    q_EVP_CIPHER_CTX_init(&ctx);
    q_EVP_CipherInit(&ctx, type, NULL, NULL, enc);
    q_EVP_CIPHER_CTX_set_key_length(&ctx, key.size());
    if (cipher == QSslKey::Rc2Cbc)
        q_EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_SET_RC2_KEY_BITS, 8 * key.size(), NULL);
    q_EVP_CipherInit(&ctx, NULL,
        reinterpret_cast<const unsigned char *>(key.constData()),
        reinterpret_cast<const unsigned char *>(iv.constData()), enc);
    q_EVP_CipherUpdate(&ctx,
        reinterpret_cast<unsigned char *>(output.data()), &len,
        reinterpret_cast<const unsigned char *>(data.constData()), data.size());
    q_EVP_CipherFinal(&ctx,
        reinterpret_cast<unsigned char *>(output.data()) + len, &i);
    len += i;
    q_EVP_CIPHER_CTX_cleanup(&ctx);

    return output.left(len);
}

QByteArray QSslKeyPrivate::decrypt(QSslKey::Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    return doCrypt(cipher, data, key, iv, 0);
}

QByteArray QSslKeyPrivate::encrypt(QSslKey::Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    return doCrypt(cipher, data, key, iv, 1);
}

QT_END_NAMESPACE

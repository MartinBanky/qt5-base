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


/*!
    \class QSslKey
    \brief The QSslKey class provides an interface for private and public keys.
    \since 4.3

    \reentrant
    \ingroup network
    \ingroup ssl
    \ingroup shared
    \inmodule QtNetwork

    QSslKey provides a simple API for managing keys.

    \sa QSslSocket, QSslCertificate, QSslCipher
*/

/*!
    \enum QSslKey::Cipher

    Describes the ciphers that can be passed to setCipher()
    for use when encrypting keys.

    \value DesEcb DES-ECB DES in ECB mode
    \value DesEde DES-EDE Two key triple DES EDE in ECB mode
    \value DesEde3 DES-EDE3 Three key triple DES EDE in ECB mode
    \value DesEdeEcb DES-EDE-ECB
    \value DesEde3Ecb DES-EDE3-ECB
    \value DesCfb64 DES-CFB64
    \value DesCfb1 DES-CFB1
    \value DesCfb8 DES-CFB8
    \value DesEdeCfb64 DES-EDE-CFB64 Two key triple DES EDE in CFB64 mode
    \value DesEde3Cfb64 DES-EDE3-CFB64 Three key triple DES EDE CFB64 mode
    \value DesEde3Cfb1 DES-EDE3-CFB1
    \value DesEde3Cfb8 DES-EDE3-CFB8
    \value DesOfb DES-OFB DES in OFB mode
    \value DesEdeOfb DES-EDE-OFB
    \value DesEde3Ofb DES-EDE3-OFB Three key triple DES EDE in OFB mode
    \value DesCbc DES-CBC DES in CBC mode
    \value DesEdeCbc DES-EDE-CBC
    \value DesEde3Cbc DES-EDE3-CBC Three key triple DES EDE in CBC mode
    \value DesxCbc DES-XCBC
    \value Rc4 RC4 128 bit RC4
    \value Rc4_40 RC4-40 40 bit RC4
    \value Rc4HmacMd5 RC4-HMAC-MD5
    \value IdeaEcb IDEA-ECB IDEA in ECB mode
    \value IdeaCfb64 IDEA-CFB64 IDEA in CFB64 mode
    \value IdeaOfb IDEA-OFB IDEA in OFB mode
    \value IdeaCbc IDEA-CBC IDEA algorithm in CBC mode
    \value Rc2Ecb RC2-ECB 128 bit RC2 in ECB mode
    \value Rc2Cbc RC2-CBC 128 bit RC2 in CBC mode
    \value Rc2_40Cbc RC2-40-CBC 40 bit RC2 in CBC mode
    \value Rc2_64Cbc RC2-64-CBC 64 bit RC2 in CBC mode
    \value Rc2Cfb64 RC2-CFB64 128 bit RC2 in CFB64 mode
    \value Rc2Ofb RC2-OFB 128 bit RC2 in OFB mode
    \value BfEcb BF-ECB Blowfish in ECB mode
    \value BfCbc BF-CBC Blowfish in CBC mode
    \value BfCfb64 BF-CFB64 Blowfish in CFB64 mode
    \value BfOfb BF-OFB Blowfish in OFB mode
    \value Cast5Ecb CAST5-ECB CAST5 in ECB mode
    \value Cast5Cbc CAST5-CBC CAST5 in CBC mode
    \value Cast5Cfb64 CAST5-CFB64 CAST5 in CFB64 mode
    \value Cast5Ofb CAST5-OFB CAST5 in OFB mode
    \value Rc5Cbc RC5-CBC RC5 cipher in CBC mode
    \value Rc5Ecb RC5-ECB RC5 cipher in ECB mode
    \value Rc5Cfb64 RC5-CFB64 RC5 cipher in CBC64 mode
    \value Rc5Ofb RC5-OFB RC5 cipher in OFB mode
    \value Aes128Ecb AES-128-ECB 128 bit AES in ECB mode
    \value Aes128Cbc AES-128-CBC 128 bit AES in CBC mode
    \value Aes128Cfb1 AES-128-CFB1 128 bit AES in 1 bit CFB mode
    \value Aes128Cfb8 AES-128-CFB8 128 bit AES in 8 bit CFB mode
    \value Aes128Cfb128 AES-128-CFB128 128 AES in 128 bit CFB mode
    \value Aes128Ofb AES-128-OFB 128 bit AES in OFB mode
    \value Aes128Ctr AES-128-CTR 128 bit AES in CTR mode
    \value Aes128Ccm AES-128-CCM 128 bit AES in CCM mode
    \value Aes128Gcm AES-128-GCM 128 bit AES in GCM mode
    \value Aes128Xts AES-128-XTS 128 bit AES in XTS mode
    \value Aes192Ecb AES-192-ECB 192 bit AES in ECB mode
    \value Aes192Cbc AES-192-CBC 192 bit AES in CBC mode
    \value Aes192Cfb1 AES-192-CFB1 192 bit AES in 1 bit CFB mode
    \value Aes192Cfb8 AES-192-CFB8 192 bit AES in 8 bit CFB mode
    \value Aes192Cfb128 AES-192-CFB128 192 bit AES in 128 bit CFB mode
    \value Aes192Ofb AES-192-OFB 192 bit AES in OFB mode
    \value Aes192Ctr AES-192-CTR 192 bit AES in CTR mode
    \value Aes192Ccm AES-192-CCM 192 bit AES in CCM mode
    \value Aes192Gcm AES-192-GCM 192 bit AES in GCM mode
    \value Aes256Ecb AES-256-ECB 256 bit AES in ECB mode
    \value Aes256Cbc AES-256-CBC 256 bit AES in CBC mode
    \value Aes256Cfb1 AES-256-CFB1 256 bit AES in 1 bit CFB mode
    \value Aes256Cfb8 AES-256-CFB8 256 bit AES in 8 bit CFB mode
    \value Aes256Cfb128 AES-256-CFB128 256 bit AES in 128 bit CFB mode
    \value Aes256Ofb AES-256-OFB 256 bit AES in OFB mode
    \value Aes256Ctr AES-256-CTR 256 bit AES in CTR mode
    \value Aes256Ccm AES-256-CCM 256 bit AES in CCM mode
    \value Aes256Gcm AES-256-GCM 256 bit AES in GCM mode
    \value Aes256Xts AES-256-XTS 256 bit AES in XTS mode
    \value Aes128CbcHmacSha1 AES-128-CBC-HMAC-SHA1
    \value Aes256CbcHmacSha1 AES-256-CBC-HMAC-SHA1
    \value Aes128CbcHmacSha256 AES-128-CBC-HMAC-SHA256
    \value Aes256CbcHmacSha256 AES-256-CBC-HMAC-SHA256
    \value Camellia128Ecb Camellia-128-ECB
    \value Camellia128Cbc Camellia-128-CBC
    \value Camellia128Cfb1 Camellia-128-CFB1
    \value Camellia128Cfb8 Camellia-128-CFB8
    \value Camellia128Cfb128 Camellia-128-CFB128
    \value Camellia128Ofb Camellia-128-OFB
    \value Camellia192Ecb Camellia-192-ECB
    \value Camellia192Cbc Camellia-192-CBC
    \value Camellia192Cfb1 Camellia-192-CFB1
    \value Camellia192Cfb8 Camellia-192-CFB8
    \value Camellia192Cfb128 Camellia-192-CFB128
    \value Camellia192Ofb Camellia-192-OFB
    \value Camellia256Ecb Camellia-256-ECB
    \value Camellia256Cbc Camellia-256-CBC
    \value Camellia256Cfb1 Camellia-256-CFB1
    \value Camellia256Cfb8 Camellia-256-CFB8
    \value Camellia256Cfb128 Camellia-256-CFB128
    \value Camellia256Ofb Camellia-256-OFB
    \value SeedEcb SEED-ECB
    \value SeedCbc SEED-CBC
    \value SeedCfb128 SEED-CFB128
    \value SeedOfb SEED-OFB
*/

#include "qsslkey.h"
#include "qsslkey_p.h"
#ifndef QT_NO_OPENSSL
#include "qsslsocket_openssl_symbols_p.h"
#endif
#include "qsslsocket.h"
#include "qsslsocket_p.h"

#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qiodevice.h>
#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

QT_BEGIN_NAMESPACE

/*!
    \fn void QSslKeyPrivate::clear(bool deep)
    \internal
 */

/*!
    \fn void QSslKeyPrivate::decodePem(const QByteArray &pem, const QByteArray &passPhrase,
                               bool deepClear)
    \internal

    Allocates a new rsa or dsa struct and decodes \a pem into it
    according to the current algorithm and type.

    If \a deepClear is true, the rsa/dsa struct is freed if it is was
    already allocated, otherwise we "leak" memory (which is exactly
    what we want for copy construction).

    If \a passPhrase is non-empty, it will be used for decrypting
    \a pem.
*/

/*!
    Constructs a null key.

    \sa isNull()
*/
QSslKey::QSslKey()
    : d(new QSslKeyPrivate)
{
}

/*!
    \internal
*/
QByteArray QSslKeyPrivate::pemHeader() const
{
    if (type == QSsl::PublicKey)
        return QByteArrayLiteral("-----BEGIN PUBLIC KEY-----");
    else if (algorithm == QSsl::Rsa)
        return QByteArrayLiteral("-----BEGIN RSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Dsa)
        return QByteArrayLiteral("-----BEGIN DSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Ec)
        return QByteArrayLiteral("-----BEGIN EC PRIVATE KEY-----");

    Q_UNREACHABLE();
    return QByteArray();
}

/*!
    \internal
*/
QByteArray QSslKeyPrivate::pemFooter() const
{
    if (type == QSsl::PublicKey)
        return QByteArrayLiteral("-----END PUBLIC KEY-----");
    else if (algorithm == QSsl::Rsa)
        return QByteArrayLiteral("-----END RSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Dsa)
        return QByteArrayLiteral("-----END DSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Ec)
        return QByteArrayLiteral("-----END EC PRIVATE KEY-----");

    Q_UNREACHABLE();
    return QByteArray();
}

/*!
    \internal

    Returns a DER key formatted as PEM.
*/
QByteArray QSslKeyPrivate::pemFromDer(const QByteArray &der, const QMap<QByteArray, QByteArray> &headers) const
{
    QByteArray pem(der.toBase64());

    const int lineWidth = 64; // RFC 1421
    const int newLines = pem.size() / lineWidth;
    const bool rem = pem.size() % lineWidth;

    // ### optimize
    for (int i = 0; i < newLines; ++i)
        pem.insert((i + 1) * lineWidth + i, '\n');
    if (rem)
        pem.append('\n'); // ###

    QByteArray extra;
    if (!headers.isEmpty()) {
        QMap<QByteArray, QByteArray>::const_iterator it = headers.constEnd();
        do {
            --it;
            extra += it.key() + ": " + it.value() + '\n';
        } while (it != headers.constBegin());
        extra += '\n';
    }
    pem.prepend(pemHeader() + '\n' + extra);
    pem.append(pemFooter() + '\n');

    return pem;
}

/*!
    \internal

    Returns a PEM key formatted as DER.
*/
QByteArray QSslKeyPrivate::derFromPem(const QByteArray &pem, QMap<QByteArray, QByteArray> *headers) const
{
    const QByteArray header = pemHeader();
    const QByteArray footer = pemFooter();

    QByteArray der(pem);

    const int headerIndex = der.indexOf(header);
    const int footerIndex = der.indexOf(footer);
    if (headerIndex == -1 || footerIndex == -1)
        return QByteArray();

    der = der.mid(headerIndex + header.size(), footerIndex - (headerIndex + header.size()));

    if (der.contains("Proc-Type:")) {
        // taken from QHttpNetworkReplyPrivate::parseHeader
        int i = 0;
        while (i < der.count()) {
            int j = der.indexOf(':', i); // field-name
            if (j == -1)
                break;
            const QByteArray field = der.mid(i, j - i).trimmed();
            j++;
            // any number of LWS is allowed before and after the value
            QByteArray value;
            do {
                i = der.indexOf('\n', j);
                if (i == -1)
                    break;
                if (!value.isEmpty())
                    value += ' ';
                // check if we have CRLF or only LF
                bool hasCR = (i && der[i-1] == '\r');
                int length = i -(hasCR ? 1: 0) - j;
                value += der.mid(j, length).trimmed();
                j = ++i;
            } while (i < der.count() && (der.at(i) == ' ' || der.at(i) == '\t'));
            if (i == -1)
                break; // something is wrong

            headers->insert(field, value);
        }
        der = der.mid(i);
    }

    return QByteArray::fromBase64(der); // ignores newlines
}

/*!
    Constructs a QSslKey by decoding the string in the byte array
    \a encoded using a specified \a algorithm and \a encoding format.
    \a type specifies whether the key is public or private.

    If the key is encoded as PEM and encrypted, \a passPhrase is used
    to decrypt it.

    After construction, use isNull() to check if \a encoded contained
    a valid key.
*/
QSslKey::QSslKey(const QByteArray &encoded, QSsl::KeyAlgorithm algorithm,
                 QSsl::EncodingFormat encoding, QSsl::KeyType type, const QByteArray &passPhrase)
    : d(new QSslKeyPrivate)
{
    d->type = type;
    d->algorithm = algorithm;
    if (encoding == QSsl::Der)
        d->decodeDer(encoded);
    else
        d->decodePem(encoded, passPhrase);

    d->bitSize = d->length();
}

/*!
    Constructs a QSslKey by reading and decoding data from a
    \a device using a specified \a algorithm and \a encoding format.
    \a type specifies whether the key is public or private.

    If the key is encoded as PEM and encrypted, \a passPhrase is used
    to decrypt it.

    After construction, use isNull() to check if \a device provided
    a valid key.
*/
QSslKey::QSslKey(QIODevice *device, QSsl::KeyAlgorithm algorithm, QSsl::EncodingFormat encoding,
                 QSsl::KeyType type, const QByteArray &passPhrase)
    : d(new QSslKeyPrivate)
{
    QByteArray encoded;
    if (device)
        encoded = device->readAll();
    d->type = type;
    d->algorithm = algorithm;
    if (encoding == QSsl::Der)
        d->decodeDer(encoded);
    else
        d->decodePem(encoded, passPhrase);

    d->bitSize = d->length();
}

/*!
    \since 5.0
    Constructs a QSslKey from a valid native key \a handle.
    \a type specifies whether the key is public or private.

    QSslKey will take ownership for this key and you must not
    free the key using the native library.
*/
QSslKey::QSslKey(Qt::HANDLE handle, QSsl::KeyType type)
    : d(new QSslKeyPrivate)
{
#ifndef QT_NO_OPENSSL
    EVP_PKEY *evpKey = reinterpret_cast<EVP_PKEY *>(handle);
    if (!evpKey || !d->fromEVP_PKEY(evpKey)) {
        d->pKey = evpKey;
        d->algorithm = QSsl::Opaque;
    } else {
        q_EVP_PKEY_free(evpKey);
    }
#else
    d->opaque = handle;
    d->algorithm = QSsl::Opaque;
#endif
    d->type = type;
    d->isNull = !d->pKey;
}

/*!
    Constructs an identical copy of \a other.
*/
QSslKey::QSslKey(const QSslKey &other) : d(other.d)
{
}

/*!
    Destroys the QSslKey object.
*/
QSslKey::~QSslKey()
{
}

/*!
    Copies the contents of \a other into this key, making the two keys
    identical.

    Returns a reference to this QSslKey.
*/
QSslKey &QSslKey::operator=(const QSslKey &other)
{
    d = other.d;
    return *this;
}

/*!
    Generates the new private key. You can call this without calling
    any of the setter functions. All variables involved have default
    values set. Only RSA or DSA keys are supported. To encrypt the key,
    call toPem() with a passphrase.
 */
void QSslKey::generatePrivateKey() const
{
    return d->generatePrivateKey();
}

/*!
    Sets the algorithm for the key.
 */
void QSslKey::setAlgorithm(const QSsl::KeyAlgorithm algorithm) const
{
    d->algorithm = algorithm;
}

/*!
    Sets the bit size for the key.
 */
void QSslKey::setBitSize(qint32 bitSize) const
{
    if (d->algorithm == QSsl::Dsa && bitSize > 1024) {
        d->bitSize = 1024;
    } else {
        d->bitSize = bitSize;
    }
}

/*!
    Sets the encryption cipher.
    \note The passphrase has to be set as well.
 */
void QSslKey::setCipher(QSslKey::Cipher cipher) const
{
    d->cipher = cipher;
}

/*!
    \fn void QSslKey::swap(QSslKey &other)
    \since 5.0

    Swaps this ssl key with \a other. This function is very fast and
    never fails.
*/

/*!
    Returns \c true if this is a null key; otherwise false.

    \sa clear()
*/
bool QSslKey::isNull() const
{
    return d->isNull;
}

/*!
    Clears the contents of this key, making it a null key.

    \sa isNull()
*/
void QSslKey::clear()
{
    d = new QSslKeyPrivate;
}

/*!
    Returns the length of the key in bits, or -1 if the key is null.
*/
int QSslKey::length() const
{
    return d->length();
}

/*!
    Returns the type of the key (i.e., PublicKey or PrivateKey).
*/
QSsl::KeyType QSslKey::type() const
{
    return d->type;
}

/*!
    Returns the key algorithm.
*/
QSsl::KeyAlgorithm QSslKey::algorithm() const
{
    return d->algorithm;
}

/*!
  Returns the key in DER encoding.

  The \a passPhrase argument should be omitted as DER cannot be
  encrypted. It will be removed in a future version of Qt.
*/
QByteArray QSslKey::toDer(const QByteArray &passPhrase) const
{
    if (d->isNull || d->algorithm == QSsl::Opaque)
        return QByteArray();

    // Encrypted DER is nonsense, see QTBUG-41038.
    if (d->type == QSsl::PrivateKey && !passPhrase.isEmpty())
        return QByteArray();

#ifndef QT_NO_OPENSSL
    QMap<QByteArray, QByteArray> headers;
    return d->derFromPem(toPem(passPhrase), &headers);
#else
    return d->derData;
#endif
}

/*!
  Returns the key in PEM encoding. The result is encrypted with
  \a passPhrase if the key is a private key and \a passPhrase is
  non-empty. If the chosen cipher is unavailable, then the message
  \a Cipher \a is \a unavailable will be returned.
*/
QByteArray QSslKey::toPem(const QByteArray &passPhrase) const
{
    return d->toPem(passPhrase);
}

/*!
    Returns a pointer to the native key handle, if it is available;
    otherwise a null pointer is returned.

    You can use this handle together with the native API to access
    extended information about the key.

    \warning Use of this function has a high probability of being
    non-portable, and its return value may vary across platforms, and
    between minor Qt releases.
*/
Qt::HANDLE QSslKey::handle() const
{
    return d->handle();
}

/*!
    Returns \c true if this key is equal to \a other; otherwise returns \c false.
*/
bool QSslKey::operator==(const QSslKey &other) const
{
    if (isNull())
        return other.isNull();
    if (other.isNull())
        return isNull();
    if (algorithm() != other.algorithm())
        return false;
    if (type() != other.type())
        return false;
    if (length() != other.length())
        return false;
    if (algorithm() == QSsl::Opaque)
        return handle() == other.handle();
    return toDer() == other.toDer();
}

/*! \fn bool QSslKey::operator!=(const QSslKey &other) const

  Returns \c true if this key is not equal to key \a other; otherwise
  returns \c false.
*/

#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug debug, const QSslKey &key)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace();
    debug << "QSslKey("
          << (key.type() == QSsl::PublicKey ? "PublicKey" : "PrivateKey")
          << ", " << (key.algorithm() == QSsl::Opaque ? "OPAQUE" :
                      (key.algorithm() == QSsl::Rsa ? "RSA" : ((key.algorithm() == QSsl::Dsa) ? "DSA" : "EC")))
          << ", " << key.length()
          << ')';
    return debug;
}
#endif

QT_END_NAMESPACE

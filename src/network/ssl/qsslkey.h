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


#ifndef QSSLKEY_H
#define QSSLKEY_H

#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qnamespace.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qsharedpointer.h>
#include <QtNetwork/qssl.h>

QT_BEGIN_NAMESPACE


#ifndef QT_NO_SSL

template <typename A, typename B> struct QPair;

class QIODevice;

class QSslKeyPrivate;
class Q_NETWORK_EXPORT QSslKey
{
public:
    enum Cipher {
        DesEcb,
        DesEde,
        DesEde3,
        DesEdeEcb,
        DesEde3Ecb,
        DesCfb64,
        DesCfb1,
        DesCfb8,
        DesEdeCfb64,
        DesEde3Cfb64,
        DesEde3Cfb1,
        DesEde3Cfb8,
        DesOfb,
        DesEdeOfb,
        DesEde3Ofb,
        DesCbc,
        DesEdeCbc,
        DesEde3Cbc,
        DesxCbc,
        Rc4,
        Rc4_40,
        Rc4HmacMd5,
        IdeaEcb,
        IdeaCfb64,
        IdeaOfb,
        IdeaCbc,
        Rc2Ecb,
        Rc2Cbc,
        Rc2_40Cbc,
        Rc2_64Cbc,
        Rc2Cfb64,
        Rc2Ofb,
        BfEcb,
        BfCbc,
        BfCfb64,
        BfOfb,
        Cast5Ecb,
        Cast5Cbc,
        Cast5Cfb64,
        Cast5Ofb,
        Rc5Cbc,
        Rc5Ecb,
        Rc5Cfb64,
        Rc5Ofb,
        Aes128Ecb,
        Aes128Cbc,
        Aes128Cfb1,
        Aes128Cfb8,
        Aes128Cfb128,
        Aes128Ofb,
        Aes128Ctr,
        Aes128Ccm,
        Aes128Gcm,
        Aes128Xts,
        Aes192Ecb,
        Aes192Cbc,
        Aes192Cfb1,
        Aes192Cfb8,
        Aes192Cfb128,
        Aes192Ofb,
        Aes192Ctr,
        Aes192Ccm,
        Aes192Gcm,
        Aes256Ecb,
        Aes256Cbc,
        Aes256Cfb1,
        Aes256Cfb8,
        Aes256Cfb128,
        Aes256Ofb,
        Aes256Ctr,
        Aes256Ccm,
        Aes256Gcm,
        Aes256Xts,
        Aes128CbcHmacSha1,
        Aes256CbcHmacSha1,
        Aes128CbcHmacSha256,
        Aes256CbcHmacSha256,
        Camellia128Ecb,
        Camellia128Cbc,
        Camellia128Cfb1,
        Camellia128Cfb8,
        Camellia128Cfb128,
        Camellia128Ofb,
        Camellia192Ecb,
        Camellia192Cbc,
        Camellia192Cfb1,
        Camellia192Cfb8,
        Camellia192Cfb128,
        Camellia192Ofb,
        Camellia256Ecb,
        Camellia256Cbc,
        Camellia256Cfb1,
        Camellia256Cfb8,
        Camellia256Cfb128,
        Camellia256Ofb,
        SeedEcb,
        SeedCbc,
        SeedCfb128,
        SeedOfb
    };

    QSslKey();
    QSslKey(const QByteArray &encoded, QSsl::KeyAlgorithm algorithm,
            QSsl::EncodingFormat format = QSsl::Pem,
            QSsl::KeyType type = QSsl::PrivateKey,
            const QByteArray &passPhrase = QByteArray());
    QSslKey(QIODevice *device, QSsl::KeyAlgorithm algorithm,
            QSsl::EncodingFormat format = QSsl::Pem,
            QSsl::KeyType type = QSsl::PrivateKey,
            const QByteArray &passPhrase = QByteArray());
    explicit QSslKey(Qt::HANDLE handle, QSsl::KeyType type = QSsl::PrivateKey);
    QSslKey(const QSslKey &other);
#ifdef Q_COMPILER_RVALUE_REFS
    QSslKey &operator=(QSslKey &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    QSslKey &operator=(const QSslKey &other);
    ~QSslKey();

    void generatePrivateKey() const;

    void setAlgorithm(const QSsl::KeyAlgorithm algorithm = QSsl::Rsa) const;
    void setBitSize(qint32 bitSize = 2048) const;
    void setCipher(QSslKey::Cipher cipher = QSslKey::DesEde3Cbc) const;

    void swap(QSslKey &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    bool isNull() const;
    void clear();

    int length() const;
    QSsl::KeyType type() const;
    QSsl::KeyAlgorithm algorithm() const;

    QByteArray toPem(const QByteArray &passPhrase = QByteArray()) const;
    QByteArray toDer(const QByteArray &passPhrase = QByteArray()) const;

    Qt::HANDLE handle() const;

    bool operator==(const QSslKey &key) const;
    inline bool operator!=(const QSslKey &key) const { return !operator==(key); }

private:
    QExplicitlySharedDataPointer<QSslKeyPrivate> d;
    friend class QSslCertificate;
    friend class QSslSocketBackendPrivate;
};

Q_DECLARE_SHARED(QSslKey)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const QSslKey &key);
#endif

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif

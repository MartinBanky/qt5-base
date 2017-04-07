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


#ifndef QSSLKEY_OPENSSL_P_H
#define QSSLKEY_OPENSSL_P_H

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API.  It exists for the convenience
// of qsslcertificate.cpp.  This header file may change from version to version
// without notice, or even be removed.
//
// We mean it.
//

#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "qsslkey.h"
#include "qsslsocket_p.h" // includes wincrypt.h

#ifndef QT_NO_OPENSSL
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#endif

QT_BEGIN_NAMESPACE

class QSslKeyPrivate
{
public:
    inline QSslKeyPrivate()
    {
        clear(false);
    }

    inline ~QSslKeyPrivate()
    { clear(); }

    void clear(bool deep = true);

#ifndef QT_NO_OPENSSL
    bool fromEVP_PKEY(EVP_PKEY *pkey);
#endif
    void decodeDer(const QByteArray &der, bool deepClear = true);
    void decodePem(const QByteArray &pem, const QByteArray &passPhrase,
                   bool deepClear = true);
    QByteArray pemHeader() const;
    QByteArray pemFooter() const;
    QByteArray pemFromDer(const QByteArray &der, const QMap<QByteArray, QByteArray> &headers) const;
    QByteArray derFromPem(const QByteArray &pem, QMap<QByteArray, QByteArray> *headers) const;

    int length() const;
    QByteArray toPem(const QByteArray &passPhrase) const;
    Qt::HANDLE handle() const;

#ifndef QT_NO_OPENSSL
    typedef const EVP_CIPHER *(*CipherType)();

    const EVP_CIPHER *getCipherStructure() const;
#endif

    void generatePrivateKey();

    bool isNull;
    QSsl::KeyType type;
    QSsl::KeyAlgorithm algorithm = QSsl::Rsa;

    qint32 bitSize = 2048;
    QSslKey::Cipher cipher = QSslKey::DesEde3Cbc;

    Q_AUTOTEST_EXPORT static QByteArray decrypt(QSslKey::Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv);
    Q_AUTOTEST_EXPORT static QByteArray encrypt(QSslKey::Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv);

    /*
     * EVP_PKEY has a pkey union already to handle the different
     * key types (Rsa, Dsa, Dh, and Ec). Plus, we need access
     * to the evp_pkey_st during certificate creation. Otherwise,
     * we either leak memory by not freeing the new EVP_PKEYs that
     * are needed or when we free the new EVP_PKEYs, the Rsa, Dsa,
     * Dh, or Ec keys get freed as well. Also, the EVP_PKEYs have
     * to be pointers, because openssl uses **EVP_PKEY for some
     * of it's function calls. Not good for batch creating
     * certificates. You would have to close your QSslKey object
     * and reopen it every time you wanted to create a new certificate.
     * The functionality stays the same.
     */
#ifndef QT_NO_OPENSSL
    EVP_PKEY *pKey = 0;
#else
    Qt::HANDLE opaque;
    QByteArray derData;
    int keyLength;
#endif

    QAtomicInt ref;

private:
    Q_DISABLE_COPY(QSslKeyPrivate)
};

QT_END_NAMESPACE

#endif // QSSLKEY_OPENSSL_P_H

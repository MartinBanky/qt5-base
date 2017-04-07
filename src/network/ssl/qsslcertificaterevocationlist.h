/****************************************************************************
**
** Copyright (C) 2017 Martin Banky
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

#ifndef QSSLCERTIFICATEREVOCATIONLIST_H
#define QSSLCERTIFICATEREVOCATIONLIST_H

#include <QtNetwork/qssl.h>
#include <QtNetwork/qsslerror.h>
#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qnamespace.h>
#include <QtCore/qsharedpointer.h>

#ifndef QT_NO_SSL

QT_BEGIN_NAMESPACE

class QSslKey;
class QIODevice;
class QSslCertificate;
class QSslRevokedCertificate;
class QSslCertificateExtension;
class QSslCertificateRevocationList;
class QSslCertificateRevocationListPrivate;

class Q_NETWORK_EXPORT QSslCertificateRevocationList
{
public:
    QSslCertificateRevocationList();
    explicit QSslCertificateRevocationList(QIODevice *device, QSsl::EncodingFormat format = QSsl::Pem);
    explicit QSslCertificateRevocationList(const QByteArray &data, QSsl::EncodingFormat format = QSsl::Pem);
    QSslCertificateRevocationList(const QSslCertificateRevocationList &other);
    ~QSslCertificateRevocationList();
#ifdef Q_COMPILER_RVALUE_REFS
    QSslCertificateRevocationList &operator=(QSslCertificateRevocationList &&other) Q_DECL_NOTHROW
    { swap(other); return *this; }
#endif
    QSslCertificateRevocationList &operator=(const QSslCertificateRevocationList &other);

    void swap(QSslCertificateRevocationList &other) Q_DECL_NOTHROW
    { qSwap(d, other.d); }

    bool operator==(const QSslCertificateRevocationList &other) const;
    inline bool operator!=(const QSslCertificateRevocationList &other) const
    { return !operator==(other); }

    QSslError::SslError addRevokedCertificates(const QList<QSslCertificate> &certificatesToRevoke) const;
    QSslError::SslError generateCertificateRevocationList(const QList<QSslCertificate> &certificatesToRevoke) const;
    QSslError::SslError removeRevokedCertificates(const QDateTime &dateTime) const;
    QSslError::SslError removeRevokedCertificates(const QList<QSslRevokedCertificate> &certificatesToRemove) const;
    QSslError::SslError verify(const QList<QSslCertificate> &caCertificates) const;

    Qt::HANDLE handle() const;
    bool isNull() const;
    bool isValid() const;

    QByteArray toDer() const;
    QByteArray toPem() const;
    QString toText() const;

    void clear();
    void setCertificateAuthority(QSslCertificate *certificate, const QSslKey &key) const;
    void setCrlNumber(const QByteArray &crlNumber) const;
    void setDuration(qint32 hours) const;
    void setSignatureAlgorithm(QSsl::SignatureAlgorithm
            signatureAlgorithm = QSsl::sha256WithRSAEncryption) const;

    // Certificate info
    QByteArray crlNumber() const;
    QByteArray signature() const;
    QByteArray version() const;
    QDateTime lastUpdate() const;
    QDateTime nextUpdate() const;
    QList<QSslCertificateExtension> extensions() const;
    QMap<QByteArray, QString> issuerInfo() const;
    QList<QSslRevokedCertificate> revokedCertificates() const;
    QSsl::SignatureAlgorithm signatureAlgorithm() const;

private:
    QExplicitlySharedDataPointer<QSslCertificateRevocationListPrivate> d;
    friend class QSslCertificateRevocationListPrivate;
};
Q_DECLARE_SHARED(QSslCertificateRevocationList)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const QSslCertificateRevocationList &certificateRevocationList);
#endif

QT_END_NAMESPACE

Q_DECLARE_METATYPE(QSslCertificateRevocationList)

#endif // QT_NO_SSL

#endif // QSSLCERTIFICATEREVOCATIONLIST_H

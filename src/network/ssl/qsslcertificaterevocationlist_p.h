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

#ifndef QSSLCERTIFICATEREVOCATIONLIST_P_H
#define QSSLCERTIFICATEREVOCATIONLIST_P_H

#include <QtNetwork/private/qtnetworkglobal_p.h>

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

#ifndef QT_NO_SSL

#include <QtNetwork/qsslkey.h>
#include <QtNetwork/qsslerror.h>
#include <QtCore/qdatetime.h>

#ifndef QT_NO_OPENSSL
#include <openssl/x509.h>
#else
struct X509_CRL;
struct X509_EXTENSION;
struct ASN1_OBJECT;
#endif

QT_BEGIN_NAMESPACE

class QSslCertificate;
class QSslRevokedCertificate;

class QSslCertificateRevocationListPrivate
{
public:
    enum SignatureAlgorithmNid {
        md2WithRSAEncryptionNid = 7,
        md4WithRSAEncryptionNid = 396,
        md5WithRSAEncryptionNid = 8,
        shaWithRSAEncryptionNid = 42,
        sha1WithRSAEncryptionNid = 65,
        dsaWithSHA1Nid = 113,
        sha224WithRSAEncryptionNid = 671,
        sha256WithRSAEncryptionNid = 668,
        sha384WithRSAEncryptionNid = 669,
        sha512WithRSAEncryptionNid = 670,
        mdc2WithRSANid = 96,
        ripemd160WithRSANid = 119,
    };

    QSslCertificateRevocationListPrivate();
    ~QSslCertificateRevocationListPrivate();

    bool null = true;
    bool valid = false;

    qint32 hours = 24;

    QByteArray m_crlNumber = 0;

    QDateTime m_lastUpdate;
    QDateTime m_nextUpdate;

    QSslCertificate *certificateAuthorityCertificate = 0;
    QSslKey certificateAuthorityKey;
    QVector<qint32> nidToSigAlgorithm;
    QList<QSslRevokedCertificate> m_revokedCertificates;
    QSsl::SignatureAlgorithm m_signatureAlgorithm = QSsl::sha256WithRSAEncryption;

#ifndef QT_NO_OPENSSL
    X509_CRL *x509Crl;
    typedef const EVP_MD *(*DigestType)();
#endif

    QAtomicInt ref;

    QSslError::SslError addRevokedCertificates(const QList<QSslCertificate> &certificatesToRevoke);
    QSslError::SslError generateCertificateRevocationList(const QList<QSslCertificate> &certificatesToRevoke);
    QSslError::SslError removeRevokedCertificates(const QDateTime &dateTime);
    QSslError::SslError removeRevokedCertificates(const QList<QSslRevokedCertificate> &certificatesToRemove);
    QSslError::SslError verify(const QList<QSslCertificate> &caCertificates);

    Qt::HANDLE handle() const;

    QByteArray toDer() const;
    QByteArray toPem() const;
    QString toText() const;

    void crlFromPem(const QByteArray &pem);
    void crlFromDer(const QByteArray &der);
    void init(const QByteArray &data, QSsl::EncodingFormat format);
    void revokeCertificates(const QList<QSslRevokedCertificate> &revokedCerts, const QByteArray &addToCrl);
    void setStartOfCrl();
    void setTimes();

    // Certificate info
    QByteArray crlNumber();
    QByteArray signature() const;
    QByteArray version() const;
    QDateTime lastUpdate();
    QDateTime nextUpdate();
    QList<QSslCertificateExtension> extensions() const;
    QMap<QByteArray, QString> issuerInfo() const;
    QList<QSslRevokedCertificate> revokedCertificates();
    QSsl::SignatureAlgorithm signatureAlgorithm();

    QByteArray QByteArrayFromX509Crl(QSsl::EncodingFormat format) const;

    qint8 addExtension(X509 *signer, X509_CRL *crl, qint32 nid, QByteArray value) const;
    QString QStringFromX509Crl() const;

    QSslError::SslError checkForErrors() const;
    QSslError::SslError signCrl();

private:
};

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif // QSSLCERTIFICATEREVOCATIONLIST_P_H

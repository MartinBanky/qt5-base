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

#ifndef QT_NO_OPENSSL

//#define DEVELOPMENT
//#define QSSLCERTIFICATEREVOCATIONLIST_DEBUG

#include <QtNetwork/qsslerror.h>
#include <QtNetwork/qsslcertificate.h>
#include <QtNetwork/qsslrevokedcertificate.h>
#include <QtNetwork/qsslcertificaterevocationlist.h>
#ifdef DEVELOPMENT
#include "qssl_p.h"
#include "qsslkey_p.h"
#include "qsslcertificate_p.h"
#include "qsslrevokedcertificate_p.h"
#include "qsslsocket_openssl_symbols_p.h"
#include "qsslcertificaterevocationlist_p.h"
#else
#include <QtNetwork/private/qssl_p.h>
#include <QtNetwork/private/qsslkey_p.h>
#include <QtNetwork/private/qsslcertificate_p.h>
#include <QtNetwork/private/qsslrevokedcertificate_p.h>
#include <QtNetwork/private/qsslsocket_openssl_symbols_p.h>
#include <QtNetwork/private/qsslcertificaterevocationlist_p.h>
#endif

QT_BEGIN_NAMESPACE

/*!
    \internal
 */
QSslError::SslError QSslCertificateRevocationListPrivate::addRevokedCertificates(
        const QList<QSslCertificate> &certificatesToRevoke)
{
    if (certificatesToRevoke.isEmpty()) {
        return QSslError::UnableToGetRevocationList;
    }

    QSslError::SslError sslError = checkForErrors();

    if (sslError) {
        return sslError;
    }

    setTimes();

    qint32 revokedCertificatesSize = m_revokedCertificates.size();
    qint32 revocationCertificatesSize = certificatesToRevoke.size();

    QByteArray addToCrl(revocationCertificatesSize, 1);

    if (revocationCertificatesSize > revokedCertificatesSize) {
        for (qint32 i = 0; i < revokedCertificatesSize; ++i) {
            for (qint32 j = 0; j < revocationCertificatesSize; ++j) {
                if (m_revokedCertificates.at(i).d->serialNumber
                        == certificatesToRevoke.at(j).d->serialNumberHex) {
                    addToCrl[j] = 0;
                    break;
                }
            }
        }
    } else {
        for (qint32 i = 0; i < revocationCertificatesSize; ++i) {
            for (qint32 j = 0; j < revokedCertificatesSize; ++j) {
                if (m_revokedCertificates.at(j).d->serialNumber
                        == certificatesToRevoke.at(i).d->serialNumberHex) {
                    addToCrl[i] = 0;
                    break;
                }
            }
        }
    }

    X509_REVOKED *revoked;

    for (qint32 i = 0; i < revocationCertificatesSize; ++i) {
        if (addToCrl.at(i)) {
            QSslRevokedCertificate revokedCert;
            revokedCert.setSerialNumber(certificatesToRevoke.at(i).d->serialNumberHex);
            revokedCert.setRevocationDate(m_lastUpdate);
            m_revokedCertificates.append(revokedCert);

            revoked = q_X509_REVOKED_new();
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
            q_X509_REVOKED_set_revocationDate(revoked, q_X509_CRL_get0_lastUpdate(x509Crl));
#else
            q_X509_REVOKED_set_revocationDate(revoked, q_X509_CRL_get_lastUpdate(x509Crl));
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL
            q_X509_REVOKED_set_serialNumber(revoked,
                    certificatesToRevoke.at(i).d->x509->cert_info->serialNumber);
            q_X509_CRL_add0_revoked(x509Crl, revoked);
        }
    }

    return signCrl();
}

/*!
    \internal
 */
qint8 QSslCertificateRevocationListPrivate::addExtension(X509 *signer, X509_CRL *crl,
        qint32 nid, QByteArray value) const
{
    X509V3_CTX ctx;

    ctx.db = 0;

    q_X509V3_set_ctx(&ctx, signer, 0, 0, crl, 0);
    X509_EXTENSION *extension = q_X509V3_EXT_conf_nid(0, &ctx, nid, value.data());

    if (extension) {
        q_X509_CRL_add_ext(crl, extension, -1);
        q_X509_EXTENSION_free(extension);

        return 1;
    } else {
        QByteArray errorMessage(512, 0);
        quint32 errorCode = q_ERR_get_error();
        q_ERR_error_string(errorCode, errorMessage.data());

        qCWarning(lcSsl, "QSslCertificateRevocationListBackendPrivate::addExtension: "
                "Error adding extension.\n%s", errorMessage.data());

        return 0;
    }
}

/*!
    \internal
 */
QSslError::SslError QSslCertificateRevocationListPrivate::checkForErrors() const
{
    if (null) {
        return QSslError::InvalidCaCertificate;
    }

    if (m_crlNumber.isEmpty()) {
        return QSslError::CrlNumberInvalid;
    }

    if (!q_X509_CRL_get_version(x509Crl)) {
        return QSslError::InvalidCrlVersion;
    }

    if (certificateAuthorityCertificate && !certificateAuthorityCertificate->isNull()) {
        if (certificateAuthorityKey.isNull()) {
            return QSslError::UnableToDecodeIssuerPrivateKey;
        } else if (!q_X509_check_private_key(certificateAuthorityCertificate->d->x509,
                certificateAuthorityKey.d->pKey)) {
            return QSslError::CaCertificateAndKeyDontMatch;
        }

        if (certificateAuthorityKey.d->algorithm == QSsl::Ec
                || certificateAuthorityKey.d->algorithm == QSsl::Opaque) {
            return QSslError::InvalidSigningKey;
        }
    } else {
        return QSslError::UnableToGetIssuerCertificate;
    }

    return QSslError::NoError;
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::crlFromDer(const QByteArray &der)
{
    qint32 size = der.size();

    if (size) {
        const unsigned char *data(reinterpret_cast<const unsigned char *>(der.constData()));

        x509Crl = q_d2i_X509_CRL(0, &data, size);

        if (x509Crl) {
            q_X509_CRL_sort(x509Crl);
            null = false;
        }
    }
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::crlFromPem(const QByteArray &pem)
{
    QByteArray text = pem;
    static const QByteArray begin = ("-----BEGIN X509 CRL-----");
    static const QByteArray end = ("-----END X509 CRL-----");

    if (text.contains(begin) && text.contains(end)) {
        text.replace('\r', "");
        text.replace('\n', "");

        qint32 beginSize = begin.size();

        text = QByteArray::fromBase64(text.mid(text.indexOf(begin) + beginSize,
                text.indexOf(end) - beginSize));
        const unsigned char *data = reinterpret_cast<const unsigned char *>(text.constData());

        x509Crl = q_d2i_X509_CRL(0, &data, text.size());

        if (x509Crl) {
            q_X509_CRL_sort(x509Crl);
            null = false;
        }
    }
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::crlNumber()
{
    if (m_crlNumber.isEmpty()) {
        ASN1_INTEGER *crlAsn1Number
                = reinterpret_cast<ASN1_INTEGER *>(q_X509_CRL_get_ext_d2i(x509Crl, NID_crl_number, 0, 0));

        if (crlAsn1Number) {
            BIGNUM *crlBigNumber = q_ASN1_INTEGER_to_BN(crlAsn1Number, 0);
            q_ASN1_STRING_free(crlAsn1Number);

            m_crlNumber = q_BN_bn2dec(crlBigNumber);
            q_BN_free(crlBigNumber);
        } else {
            m_crlNumber = "<None>";
        }
    }

    return m_crlNumber;
}

/*!
    \internal
 */
QList<QSslCertificateExtension> QSslCertificateRevocationListPrivate::extensions() const
{
    QList<QSslCertificateExtension> extensions;

    if (!x509Crl) {
        return extensions;
    }

    qint32 count = q_X509_CRL_get_ext_count(x509Crl);
    extensions.reserve(count);

    for (qint32 i = 0; i < count; ++i) {
        X509_EXTENSION *extension = q_X509_CRL_get_ext(x509Crl, i);
        extensions.append(QSslCertificatePrivate::convertExtension(extension));
    }

    return extensions;
}

/*!
    \internal
 */
QSslError::SslError  QSslCertificateRevocationListPrivate::generateCertificateRevocationList(
        const QList<QSslCertificate> &certificatesToRevoke)
{
    if (!certificateAuthorityCertificate || certificateAuthorityCertificate->isNull()) {
        return QSslError::UnableToGetIssuerCertificate;
    }

    setStartOfCrl();
    null = false;

    return addRevokedCertificates(certificatesToRevoke);
}

/*!
    \internal
 */
Qt::HANDLE QSslCertificateRevocationListPrivate::handle() const
{
    return Qt::HANDLE(x509Crl);
}

/*!
    \internal
 */
QMap<QByteArray, QString> QSslCertificateRevocationListPrivate::issuerInfo() const
{
    QByteArray objName;
    unsigned char *data = 0;
    QMap<QByteArray, QString> info;

    X509_NAME_ENTRY *nameEntry;
    X509_NAME *x509Name(q_X509_CRL_get_issuer(x509Crl));

    qint32 entrySize;
    qint32 count(q_X509_NAME_entry_count(x509Name));

    for (qint32 i = 0; i < count; ++i) {
        nameEntry = q_X509_NAME_get_entry(x509Name, i);
        objName = QSslCertificatePrivate::asn1ObjectName(q_X509_NAME_ENTRY_get_object(nameEntry));
        entrySize = q_ASN1_STRING_to_UTF8(&data, q_X509_NAME_ENTRY_get_data(nameEntry));
        info.insert(objName, QString::fromUtf8(reinterpret_cast<char *>(data), entrySize));
        q_CRYPTO_free(data);
    }

    return info;
}

/*!
    \internal
 */
QDateTime QSslCertificateRevocationListPrivate::lastUpdate()
{
    if (!m_lastUpdate.isValid()) {
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        m_lastUpdate = q_getTimeFromASN1(q_X509_CRL_get0_lastUpdate(x509Crl));
#else
        m_lastUpdate = q_getTimeFromASN1(q_X509_CRL_get_lastUpdate(x509Crl));
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL
    }

    return m_lastUpdate;
}

/*!
    \internal
 */
QDateTime QSslCertificateRevocationListPrivate::nextUpdate()
{
    if (!m_nextUpdate.isValid()) {
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        m_nextUpdate = q_getTimeFromASN1(q_X509_CRL_get0_nextUpdate(x509Crl));
#else
        m_nextUpdate = q_getTimeFromASN1(q_X509_CRL_get_nextUpdate(x509Crl));
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL
    }

    return m_nextUpdate;
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::QByteArrayFromX509Crl(QSsl::EncodingFormat format) const
{
    if (!x509Crl) {
        qCWarning(lcSsl, "QSslCertificateRevocationListPrivate::QByteArrayFromX509Crl: null x509Crl");
        return QByteArray();
    }

    if (format == QSsl::Pem) {
        BIO *bio = q_BIO_new(q_BIO_s_mem());

        q_PEM_write_bio_X509_CRL(bio, x509Crl);

        qint32 size = q_i2d_X509_CRL(x509Crl, 0) * 2;
        QByteArray x509CrlString(size, '0');

        size = q_BIO_read(bio, x509CrlString.data(), size);

        q_BIO_free(bio);

        return x509CrlString.left(size);
    } else {
        qint32 size = q_i2d_X509_CRL(x509Crl, 0);
        QByteArray x509CrlString(size, '0');
        unsigned char *data = reinterpret_cast<unsigned char *>(x509CrlString.data());
        size = q_i2d_X509_CRL(x509Crl, &data);

        return x509CrlString.left(size);
    }
}

/*!
    \internal
 */
QString QSslCertificateRevocationListPrivate::QStringFromX509Crl() const
{
    if (!x509Crl) {
        qCWarning(lcSsl, "QSslCertificateRevocationListPrivate::QStringFromX509Crl: null x509Crl");
        return QString();
    }

    BIO *bio = q_BIO_new(q_BIO_s_mem());

    q_X509_CRL_print(bio, x509Crl);

    qint32 size;
    QByteArray x509CrlString;
    QByteArray buffer(16384, 0);

    do {
        size = q_BIO_read(bio, buffer.data(), buffer.size());
        x509CrlString.append(buffer.left(size));
    } while (size > 0);

    q_BIO_free(bio);

    return QString::fromLatin1(x509CrlString);
}

/*!
    \internal
 */
QSslError::SslError QSslCertificateRevocationListPrivate::removeRevokedCertificates(
        const QDateTime &dateTime)
{
    if (!dateTime.isValid()) {
        return QSslError::InvalidDateTime;
    }

    QSslError::SslError sslError = checkForErrors();

    if (sslError) {
        return sslError;
    }

    setStartOfCrl();
    setTimes();

    QList<QSslRevokedCertificate> revokedCertificates = m_revokedCertificates;
    qint32 revokedCertificatesSize = revokedCertificates.size();
    QByteArray addToCrl(revokedCertificatesSize, 1);

    m_revokedCertificates.clear();

    for (qint32 i = 0; i < revokedCertificatesSize; ++i) {
        if (revokedCertificates.at(i).d->revocationDate < dateTime) {
            addToCrl[i] = 0;
        }
    }

    revokeCertificates(revokedCertificates, addToCrl);

    return signCrl();
}

/*!
    \internal
 */
QSslError::SslError QSslCertificateRevocationListPrivate::removeRevokedCertificates(
        const QList<QSslRevokedCertificate> &certificatesToRemove)
{
    if (certificatesToRemove.isEmpty()) {
        return QSslError::UnableToGetRevocationList;
    }

    QSslError::SslError sslError = checkForErrors();

    if (sslError) {
        return sslError;
    }

    setStartOfCrl();
    setTimes();

    QList<QSslRevokedCertificate> revokedCertificates = m_revokedCertificates;
    qint32 revokedCertificatesSize = revokedCertificates.size();
    qint32 removedCertificatesSize = certificatesToRemove.size();
    QByteArray addToCrl(removedCertificatesSize, 1);

    m_revokedCertificates.clear();

    if (removedCertificatesSize > revokedCertificatesSize) {
        for (qint32 i = 0; i < revokedCertificatesSize; ++i) {
            for (qint32 j = 0; j < removedCertificatesSize; ++j) {
                if (revokedCertificates.at(i).d->serialNumber
                        == certificatesToRemove.at(j).d->serialNumber) {
                    addToCrl[j] = 0;
                    break;
                }
            }
        }
    } else {
        for (qint32 i = 0; i < removedCertificatesSize; ++i) {
            for (qint32 j = 0; j < revokedCertificatesSize; ++j) {
                if (revokedCertificates.at(j).d->serialNumber
                        == certificatesToRemove.at(i).d->serialNumber) {
                    addToCrl[i] = 0;
                    break;
                }
            }
        }
    }

    revokeCertificates(certificatesToRemove, addToCrl);

    return signCrl();
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::revokeCertificates(
        const QList<QSslRevokedCertificate> &revokedCerts, const QByteArray &addToCrl)
{
    X509_REVOKED *revoked;
    BIGNUM *serialBigNumber = q_BN_new();
    ASN1_INTEGER *serialAsn1Integer = ASN1_STRING_new();
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ASN1_TIME *lastUpdate = q_X509_CRL_get0_nextUpdate(x509Crl);
#else
    ASN1_TIME *lastUpdate = q_X509_CRL_get_nextUpdate(x509Crl);
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL

    for (qint32 i = 0; i < revokedCerts.size(); ++i) {
        if (addToCrl.at(i)) {
            QSslRevokedCertificate revokedCert;
            revokedCert.setSerialNumber(revokedCerts.at(i).d->serialNumber);
            revokedCert.setRevocationDate(m_lastUpdate);
            m_revokedCertificates.append(revokedCert);

            revoked = q_X509_REVOKED_new();

            q_BN_hex2bn(&serialBigNumber, revokedCerts.at(i).d->serialNumber.data());
            q_BN_to_ASN1_INTEGER(serialBigNumber, serialAsn1Integer);
            q_X509_REVOKED_set_serialNumber(revoked, serialAsn1Integer);

            q_X509_REVOKED_set_revocationDate(revoked, lastUpdate);
            q_X509_CRL_add0_revoked(x509Crl, revoked);
        }
    }

    q_BN_free(serialBigNumber);
    q_ASN1_STRING_free(serialAsn1Integer);
}

/*!
    \internal
 */
QList<QSslRevokedCertificate> QSslCertificateRevocationListPrivate::revokedCertificates()
{
    if (m_revokedCertificates.isEmpty()) {
        X509_REVOKED *revoked;

        for (qint32 i = 0; i < q_SKM_sk_num(X509_REVOKED, q_X509_CRL_get_REVOKED(x509Crl)); ++i) {
            QSslRevokedCertificate revokedCert;

            revoked = q_SKM_sk_value(X509_REVOKED, q_X509_CRL_get_REVOKED(x509Crl), i);
            revokedCert.setSerialNumber(QByteArray(
                    reinterpret_cast<const char *>(revoked->serialNumber->data),
                    revoked->serialNumber->length).toHex().toUpper());
            revokedCert.setRevocationDate(q_getTimeFromASN1(revoked->revocationDate));

            m_revokedCertificates.append(revokedCert);
        }
    }

    return m_revokedCertificates;
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::setStartOfCrl()
{
    if (!null) {
        q_X509_CRL_free(x509Crl);
        x509Crl = q_X509_CRL_new();
    }

    q_X509_CRL_set_version(x509Crl, 1);
    q_X509_CRL_set_issuer_name(x509Crl, certificateAuthorityCertificate->d->x509->cert_info->subject);
    addExtension(certificateAuthorityCertificate->d->x509, x509Crl,
            NID_authority_key_identifier, "keyid:always");
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::setTimes()
{
    ASN1_TIME *time(static_cast<ASN1_TIME *>(q_ASN1_STRING_type_new(V_ASN1_UTCTIME)));

    q_X509_gmtime_adj(time, 0);
    m_lastUpdate = QDateTime::currentDateTime().toUTC();
    q_X509_CRL_set_lastUpdate(x509Crl, time);

    q_X509_time_adj_ex(time, 0, hours * 3600, 0);
    m_nextUpdate = m_lastUpdate.addSecs(hours * 3600);
    q_X509_CRL_set_nextUpdate(x509Crl, time);
    q_ASN1_STRING_free(static_cast<ASN1_STRING *>(time));
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::signature() const
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    const ASN1_BIT_STRING *x509Signature(
            static_cast<ASN1_BIT_STRING *>(q_ASN1_STRING_type_new(V_ASN1_BIT_STRING)));
    q_X509_CRL_get0_signature(x509Crl, &x509Signature, 0);

    qint32 length = q_ASN1_STRING_length(x509Signature);
    const unsigned char *sig = q_ASN1_STRING_get0_data(signature);

    QByteArray signature = reinterpret_cast<const signed char *>(sig), length;

    q_ASN1_STRING_free(static_cast<ASN1_BIT_STRING *>(x509Signature));

    return signature;
#else
    return QByteArray(reinterpret_cast<const char*>(
            x509Crl->signature->data), x509Crl->signature->length).toHex();
#endif //  OPENSSL_VERSION_NUMBER >= 0x1010000fL
}

/*!
    \internal
 */
QSsl::SignatureAlgorithm QSslCertificateRevocationListPrivate::signatureAlgorithm()
{
    qint32 nid;
    ASN1_OBJECT *aoid;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    X509_ALGOR *sigAlgorithm = q_X509_ALGOR_new();
    q_X509_CRL_get0_signature(x509Crl, 0, &sigAlgorithm);

    q_X509_ALGOR_get0(&aoid, 0, 0, sigAlgorithm);
    nid = OBJ_obj2nid(aoid);

    q_X509_ALGOR_free(sigAlgorithm);
#else

    q_X509_ALGOR_get0(&aoid, 0, 0, x509Crl->sig_alg);
    nid = OBJ_obj2nid(aoid);
#endif //  OPENSSL_VERSION_NUMBER >= 0x1010000fL

    if (nid) {
        for (quint8 i = 0; i < nidToSigAlgorithm.size(); ++i) {
            if (nid == nidToSigAlgorithm.at(i)) {
                m_signatureAlgorithm = static_cast<QSsl::SignatureAlgorithm>(i);
                break;
            }
        }
    }

    q_ASN1_OBJECT_free(aoid);

    return m_signatureAlgorithm;
}

/*!
    \internal
 */
QSslError::SslError QSslCertificateRevocationListPrivate::signCrl()
{
    q_X509_CRL_sort(x509Crl);

    ASN1_INTEGER *crlAsn1Number = static_cast<ASN1_INTEGER *>(q_ASN1_STRING_type_new(V_ASN1_INTEGER));
    q_ASN1_INTEGER_set(crlAsn1Number, m_crlNumber.toLong());
    q_X509_CRL_add1_ext_i2d(x509Crl, NID_crl_number, crlAsn1Number, 0, X509V3_ADD_REPLACE);
    q_ASN1_STRING_free(static_cast<ASN1_STRING *>(crlAsn1Number));

    DigestType digestType[] = {
        q_EVP_md2,
        q_EVP_md4,
        q_EVP_md5,
        q_EVP_sha,
        q_EVP_sha1,
        q_EVP_dss1,
        q_EVP_sha224,
        q_EVP_sha256,
        q_EVP_sha384,
        q_EVP_sha512,
        q_EVP_mdc2,
        q_EVP_ripemd160
    };

    const EVP_MD *digest = digestType[m_signatureAlgorithm]();

    if (!digest) {
        return QSslError::SignatureAlgorithmUnavailable;
    }

    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pkctx(0);

    q_EVP_MD_CTX_init(&mctx);
    q_EVP_DigestSignInit(&mctx, &pkctx, digest, 0, certificateAuthorityKey.d->pKey);
    q_X509_CRL_sign_ctx(x509Crl, &mctx);
    q_EVP_MD_CTX_cleanup(&mctx);

#ifdef QSSLCERTIFICATEREVOCATIONLIST_DEBUG
    X509_CRL_print_fp(stdout, x509Crl);
#endif

    return QSslError::NoError;
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::toDer() const
{
    if (!x509Crl) {
        return QByteArray();
    }

    return QByteArrayFromX509Crl(QSsl::Der);
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::toPem() const
{
    if (!x509Crl) {
        return QByteArray();
    }

    return QByteArrayFromX509Crl(QSsl::Pem);
}

/*!
    \internal
 */
QString QSslCertificateRevocationListPrivate::toText() const
{
    if (!x509Crl) {
        return QString();
    }

    return QStringFromX509Crl();
}

/*!
    \internal
 */
QSslError::SslError QSslCertificateRevocationListPrivate::verify(
        const QList<QSslCertificate> &caCertificates)
{
    if (caCertificates.count() <= 0) {
        return QSslError::UnableToGetIssuerCertificate;
    }

    X509_STORE *certStore(q_X509_STORE_new());

    if (!certStore) {
        qCWarning(lcSsl) << "Unable to create certificate store";
        return QSslError::UnspecifiedError;
    }

    bool emptyCertStore(true);
    const QDateTime now(QDateTime::currentDateTimeUtc());

    for (const QSslCertificate &caCertificate : caCertificates) {
        // From https://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html:
        //
        // If several CA certificates matching the name, key identifier, and
        // serial number condition are available, only the first one will be
        // examined. This may lead to unexpected results if the same CA
        // certificate is available with different expiration dates. If a
        // ``certificate expired'' verification error occurs, no other
        // certificate will be searched. Make sure to not have expired
        // certificates mixed with valid ones.
        //
        // See also: QSslContext::fromConfiguration()
        if (caCertificate.expiryDate() >= now) {
            emptyCertStore = false;
            q_X509_STORE_add_cert(certStore, caCertificate.d->x509);
        }
    }

    if (emptyCertStore) {
        q_X509_STORE_free(certStore);
        return QSslError::UnableToGetIssuerCertificate;
    }

    X509_STORE_CTX *storeContext(q_X509_STORE_CTX_new());

    if (!storeContext) {
        q_X509_STORE_free(certStore);
        return QSslError::UnspecifiedError;
    }

    if (!q_X509_STORE_CTX_init(storeContext, certStore, 0, 0)) {
        q_X509_STORE_CTX_free(storeContext);
        q_X509_STORE_free(certStore);
        return QSslError::UnspecifiedError;
    }

    X509_OBJECT x509Objext;
    qint32 i = q_X509_STORE_get_by_subject(storeContext, X509_LU_X509,
            q_X509_CRL_get_issuer(x509Crl), &x509Objext);

    if (i <= 0) {
        q_X509_STORE_CTX_free(storeContext);
        q_X509_STORE_free(certStore);
        q_X509_OBJECT_free_contents(&x509Objext);
        return QSslError::UnableToGetIssuerCertificate;
    }

    EVP_PKEY *pkey = q_X509_get_pubkey(x509Objext.data.x509);
    q_X509_OBJECT_free_contents(&x509Objext);

    if (!pkey) {
        q_X509_STORE_CTX_free(storeContext);
        q_X509_STORE_free(certStore);
        q_EVP_PKEY_free(pkey);
        return QSslError::UnableToDecodeIssuerPublicKey;
    }

    i = q_X509_CRL_verify(x509Crl, pkey);
    q_EVP_PKEY_free(pkey);

    if (i < 0) {
        q_X509_STORE_CTX_free(storeContext);
        q_X509_STORE_free(certStore);
        return QSslError::UnspecifiedError;
    }

    q_X509_STORE_free(certStore);
    q_X509_STORE_CTX_free(storeContext);

    if (i == 0) {
        valid = false;
    } else {
        valid = true;
    }

    return QSslError::NoError;
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::version() const
{
    return QByteArray::number(qlonglong(q_X509_CRL_get_version(x509Crl)) + 1);
}

QT_END_NAMESPACE

#endif // QT_NO_OPENSSL

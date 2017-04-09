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
#include <QtCore/qbytearraymatcher.h>

#ifdef DEVELOPMENT
#include "qssl_p.h"
#include "qsslkey_p.h"
#include "qsslcertificate_p.h"
#include "qsslrevokedcertificate_p.h"
#include "qsslsocket_openssl_symbols_p.h"
#include "qsslcertificaterevocationlist_p.h"
#endif

#include <QtNetwork/private/qssl_p.h>
#include <QtNetwork/private/qsslkey_p.h>
#include <QtNetwork/private/qsslcertificate_p.h>
#include <QtNetwork/private/qsslrevokedcertificate_p.h>
#include <QtNetwork/private/qsslsocket_openssl_symbols_p.h>
#include <QtNetwork/private/qsslcertificaterevocationlist_p.h>

QT_BEGIN_NAMESPACE

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::addRevokedCertificates(
        const QList<QSslCertificate> &certificatesToRevoke, QSslError *sslError)
{
    if (!certificatesToRevoke.isEmpty()) {
        if (checkForErrors(sslError)) {
            setTimes();

            const qint32 revokedCertificatesSize = m_revokedCertificates.size();
            const qint32 revocationCertificatesSize = certificatesToRevoke.size();

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
                            q_X509_get_serialNumber(certificatesToRevoke.at(i).d->x509));
                    q_X509_CRL_add0_revoked(x509Crl, revoked);
                }
            }

            signCrl();
        }
    } else {
        if (sslError)
            sslError->setError(QSslError::UnableToGetRevocationList);
        return;
    }
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
bool QSslCertificateRevocationListPrivate::checkForErrors(QSslError *sslError) const
{
    bool noErrors = true;

    if (null) {
        if (sslError)
            sslError->setError(QSslError::InvalidCaCertificate);
        noErrors = false;
        return noErrors;
    }

    if (m_crlNumber.isEmpty()) {
        if (sslError)
            sslError->setError(QSslError::CrlNumberInvalid);
        noErrors = false;
        return noErrors;
    }

    if (!q_X509_CRL_get_version(x509Crl)) {
        if (sslError)
            sslError->setError(QSslError::InvalidCrlVersion);
        noErrors = false;
        return noErrors;
    }

    if (certificateAuthorityCertificate && !certificateAuthorityCertificate->isNull()) {
        if (certificateAuthorityKey.isNull()) {
            if (sslError)
                sslError->setError(QSslError::UnableToDecodeIssuerPrivateKey);
            return noErrors;
            noErrors = false;
        } else if (!q_X509_check_private_key(certificateAuthorityCertificate->d->x509,
                certificateAuthorityKey.d->pKey)) {
            if (sslError)
                sslError->setError(QSslError::CaCertificateAndKeyDontMatch);
            noErrors = false;
            return noErrors;
        }

        if (certificateAuthorityKey.d->algorithm == QSsl::Ec
                || certificateAuthorityKey.d->algorithm == QSsl::Opaque) {
            if (sslError)
                sslError->setError(QSslError::InvalidSigningKey);
            noErrors = false;
            return noErrors;
        }
    } else {
        if (sslError)
            sslError->setError(QSslError::UnableToGetIssuerCertificate);
        noErrors = false;
        return noErrors;
    }

    return noErrors;
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::crlFromDer(const QByteArray &der)
{
    const qint32 size = der.size();

    if (size) {
        auto *data = reinterpret_cast<const unsigned char *>(der.constData());

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
    static const auto begin = qMakeStaticByteArrayMatcher("-----BEGIN X509 CRL-----");
    static const auto end = qMakeStaticByteArrayMatcher("-----END X509 CRL-----");

    if (begin.indexIn(text) != -1 && end.indexIn(text) ) {
        text = text.simplified();

        const qint32 beginSize = begin.pattern().size();

        text = QByteArray::fromBase64(text.mid(begin.indexIn(text) + beginSize,
                end.indexIn(text) - beginSize));
        auto *data = reinterpret_cast<const unsigned char *>(text.constData());

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

    if (x509Crl) {
        qint32 count = q_X509_CRL_get_ext_count(x509Crl);
        extensions.reserve(count);

        for (qint32 i = 0; i < count; ++i) {
            X509_EXTENSION *extension = q_X509_CRL_get_ext(x509Crl, i);
            extensions.append(QSslCertificatePrivate::convertExtension(extension));
        }
    }

    return extensions;
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::generateCertificateRevocationList(
        const QList<QSslCertificate> &certificatesToRevoke, QSslError *sslError)
{
    if (certificateAuthorityCertificate && !certificateAuthorityCertificate->isNull()) {
        setStartOfCrl();
        null = false;
        addRevokedCertificates(certificatesToRevoke);
    }else{
        if (sslError)
            sslError->setError(QSslError::UnableToGetIssuerCertificate);
    }
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
    X509_NAME *x509Name = q_X509_CRL_get_issuer(x509Crl);

    qint32 entrySize;
    const qint32 count = q_X509_NAME_entry_count(x509Name);

    for (qint32 i = 0; i < count; ++i) {
        nameEntry = q_X509_NAME_get_entry(x509Name, i);
        objName = QSslCertificatePrivate::asn1ObjectName(q_X509_NAME_ENTRY_get_object(nameEntry));
        entrySize = q_ASN1_STRING_to_UTF8(&data, q_X509_NAME_ENTRY_get_data(nameEntry));
        info.insert(objName, QString::fromUtf8(reinterpret_cast<char *>(data), entrySize));
        q_OPENSSL_free(data);
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
    if (x509Crl) {
        qint32 size;
        BIO *bio = q_BIO_new(q_BIO_s_mem());

        if (format == QSsl::Pem) {
            q_PEM_write_bio_X509_CRL(bio, x509Crl);
            size = static_cast<qint32>(q_BIO_number_written(bio));
        } else {
            q_i2d_X509_CRL_bio(bio, x509Crl);
            size = static_cast<qint32>(q_BIO_number_written(bio));
        }

        QByteArray x509CrlString(size, '0');
        size = q_BIO_read(bio, x509CrlString.data(), size);
        q_BIO_free(bio);

        return x509CrlString.left(size);
    } else {
        qCWarning(lcSsl, "QSslCertificateRevocationListPrivate::QByteArrayFromX509Crl: null x509Crl");
        return QByteArray();
    }
}

/*!
    \internal
 */
QString QSslCertificateRevocationListPrivate::QStringFromX509Crl() const
{
    if (x509Crl) {
        BIO *bio = q_BIO_new(q_BIO_s_mem());

        q_X509_CRL_print(bio, x509Crl);

        qint32 size = static_cast<qint32>(q_BIO_number_written(bio));
        QByteArray x509CrlString(size, 0);

        size = q_BIO_read(bio, x509CrlString.data(), size);
        q_BIO_free(bio);

        return QString::fromLatin1(x509CrlString.left(size));
    } else {
        qCWarning(lcSsl, "QSslCertificateRevocationListPrivate::QStringFromX509Crl: null x509Crl");
        return QString();
    }
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::removeRevokedCertificates(
        const QDateTime &dateTime, QSslError *sslError)
{
    if (dateTime.isValid()) {
        if (checkForErrors(sslError)) {
            setStartOfCrl();
            setTimes();

            const QList<QSslRevokedCertificate> revokedCertificates = m_revokedCertificates;
            const qint32 revokedCertificatesSize = revokedCertificates.size();
            QByteArray addToCrl(revokedCertificatesSize, 1);

            m_revokedCertificates.clear();

            for (qint32 i = 0; i < revokedCertificatesSize; ++i) {
                if (revokedCertificates.at(i).d->revocationDate < dateTime) {
                    addToCrl[i] = 0;
                }
            }

            revokeCertificates(revokedCertificates, addToCrl);

            signCrl();
        }
    } else {
        if (sslError)
            sslError->setError(QSslError::InvalidDateTime);
    }
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::removeRevokedCertificates(
        const QList<QSslRevokedCertificate> &certificatesToRemove, QSslError *sslError)
{
    if (!certificatesToRemove.isEmpty()) {
        if (checkForErrors(sslError)) {
            setStartOfCrl();
            setTimes();

            const QList<QSslRevokedCertificate> revokedCertificates = m_revokedCertificates;
            const qint32 revokedCertificatesSize = revokedCertificates.size();
            const qint32 removedCertificatesSize = certificatesToRemove.size();
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

            signCrl();
        }
    } else{
        if (sslError)
            sslError->setError(QSslError::UnableToGetRevocationList);
    }
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
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        BIGNUM *serialBigNumber
        ASN1_INTEGER *serialAsn1Number;
        QByteArray serialNumber;
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL

        for (qint32 i = 0; i < q_SKM_sk_num(X509_REVOKED, q_X509_CRL_get_REVOKED(x509Crl)); ++i) {
            QSslRevokedCertificate revokedCert;

            revoked = q_SKM_sk_value(X509_REVOKED, q_X509_CRL_get_REVOKED(x509Crl), i);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
            serialAsn1Number = q_X509_REVOKED_get0_serialNumber(revoked);
            serialBigNumber = q_ASN1_INTEGER_to_BN(serialAsn1Number, 0);
            q_ASN1_STRING_free(serialAsn1Number);

            serialNumber = q_BN_bn2dec(serialBigNumber);
            q_BN_free(serialBigNumber);

            revokedCert.setSerialNumber(serialNumber.toHex().toUpper());
            revokedCert.setRevocationDate(q_getTimeFromASN1(q_X509_REVOKED_get0_revocationDate(revoked)));
#else
            revokedCert.setSerialNumber(QByteArray(
                    reinterpret_cast<const char *>(revoked->serialNumber->data),
                    revoked->serialNumber->length).toHex().toUpper());
            revokedCert.setRevocationDate(q_getTimeFromASN1(revoked->revocationDate));
#endif // OPENSSL_VERSION_NUMBER >= 0x1010000fL

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
    q_X509_CRL_set_issuer_name(x509Crl,
            q_X509_get_subject_name(certificateAuthorityCertificate->d->x509));
    addExtension(certificateAuthorityCertificate->d->x509, x509Crl,
            NID_authority_key_identifier, "keyid:always");
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::setTimes()
{
    ASN1_TIME *time = static_cast<ASN1_TIME *>(q_ASN1_STRING_type_new(V_ASN1_UTCTIME));

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

    const qint32 length = q_ASN1_STRING_length(x509Signature);
    const unsigned char *sig = q_ASN1_STRING_get0_data(signature);

    QByteArray signature(reinterpret_cast<const char *>(sig), length);

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
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    const qint32 nid = q_X509_CRL_get_signature_nid(x509Crl);
#else
    ASN1_OBJECT *aoid;
    q_X509_ALGOR_get0(&aoid, 0, 0, x509Crl->sig_alg);
    const qint32 nid = OBJ_obj2nid(aoid);
    q_ASN1_OBJECT_free(aoid);
#endif //  OPENSSL_VERSION_NUMBER >= 0x1010000fL

    if (nid) {
        for (quint8 i = 0; i < nidToSigAlgorithm.size(); ++i) {
            if (nid == nidToSigAlgorithm.at(i)) {
                m_signatureAlgorithm = static_cast<QSsl::SignatureAlgorithm>(i);
                break;
            }
        }
    }

    return m_signatureAlgorithm;
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::signCrl(QSslError *sslError)
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

    if (digest) {
        EVP_MD_CTX mctx;
        EVP_PKEY_CTX *pkctx = 0;

        q_EVP_MD_CTX_init(&mctx);
        q_EVP_DigestSignInit(&mctx, &pkctx, digest, 0, certificateAuthorityKey.d->pKey);
        q_X509_CRL_sign_ctx(x509Crl, &mctx);
        q_EVP_MD_CTX_cleanup(&mctx);

#ifdef QSSLCERTIFICATEREVOCATIONLIST_DEBUG
        X509_CRL_print_fp(stdout, x509Crl);
#endif
    } else {
        if (sslError)
            sslError->setError(QSslError::SignatureAlgorithmUnavailable);
    }
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::toDer() const
{
    return QByteArrayFromX509Crl(QSsl::Der);
}

/*!
    \internal
 */
QByteArray QSslCertificateRevocationListPrivate::toPem() const
{
    return QByteArrayFromX509Crl(QSsl::Pem);
}

/*!
    \internal
 */
QString QSslCertificateRevocationListPrivate::toText() const
{
    return QStringFromX509Crl();
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::verify(
        const QList<QSslCertificate> &caCertificates, QSslError *sslError)
{
    if (caCertificates.count() <= 0) {
        X509_STORE *certStore = q_X509_STORE_new();

        if (Q_UNLIKELY(!certStore)) {
            qCWarning(lcSsl) << "Unable to create certificate store";

            if (sslError)
                sslError->setError(QSslError::UnspecifiedError);
            return;
        }

        bool emptyCertStore = true;
        const auto now = QDateTime::currentDateTimeUtc();

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

        if (Q_UNLIKELY(emptyCertStore)) {
            q_X509_STORE_free(certStore);

            if (sslError)
                sslError->setError(QSslError::UnableToGetIssuerCertificate);
            return;
        }

        X509_STORE_CTX *storeContext = q_X509_STORE_CTX_new();

        if (Q_UNLIKELY(!storeContext)) {
            q_X509_STORE_free(certStore);

            if (sslError)
                sslError->setError(QSslError::UnspecifiedError);
            return;
        }

        if (Q_UNLIKELY(!q_X509_STORE_CTX_init(storeContext, certStore, 0, 0))) {
            q_X509_STORE_CTX_free(storeContext);
            q_X509_STORE_free(certStore);

            if (sslError)
                sslError->setError(QSslError::UnspecifiedError);
            return;
        }

        X509_OBJECT x509Object;
        qint32 i = q_X509_STORE_get_by_subject(storeContext, X509_LU_X509,
                q_X509_CRL_get_issuer(x509Crl), &x509Object);

        if (Q_UNLIKELY(i <= 0)) {
            q_X509_STORE_CTX_free(storeContext);
            q_X509_STORE_free(certStore);
            q_X509_OBJECT_free_contents(&x509Object);

            if (sslError)
                sslError->setError(QSslError::UnableToGetIssuerCertificate);
            return;
        }

        EVP_PKEY *pkey = q_X509_get_pubkey(x509Object.data.x509);
        q_X509_OBJECT_free_contents(&x509Object);

        if (Q_UNLIKELY(!pkey)) {
            q_X509_STORE_CTX_free(storeContext);
            q_X509_STORE_free(certStore);
            q_EVP_PKEY_free(pkey);

            if (sslError)
                sslError->setError(QSslError::UnableToDecodeIssuerPublicKey);
            return;
        }

        i = q_X509_CRL_verify(x509Crl, pkey);
        q_EVP_PKEY_free(pkey);

        if (Q_UNLIKELY(i < 0)) {
            q_X509_STORE_CTX_free(storeContext);
            q_X509_STORE_free(certStore);

            if (sslError)
                sslError->setError(QSslError::UnspecifiedError);
            return;
        }

        q_X509_STORE_free(certStore);
        q_X509_STORE_CTX_free(storeContext);

        i == 0 ? valid = false : valid = true;
    } else {
        if (sslError)
            sslError->setError(QSslError::UnableToGetIssuerCertificate);
    }

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

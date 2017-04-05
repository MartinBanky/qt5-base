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

#include <QtNetwork/qtnetworkglobal.h>

#include <QtNetwork/qsslkey.h>
#include <QtCore/qiodevice.h>
#include <QtCore/qlist.h>

//#define DEVELOPMENT

#ifdef DEVELOPMENT
#include "qsslsocket_openssl_symbols_p.h"
#include "qsslcertificaterevocationlist.h"
#include "qsslcertificaterevocationlist_p.h"
#include "../../corelib/thread/qmutexpool_p.h"
#include <QtCore/qmutex.h>
#endif

#include <QtNetwork/qsslcertificate.h>
#include <QtNetwork/qsslrevokedcertificate.h>
#include <QtNetwork/qsslcertificateextension.h>
#include <QtNetwork/qsslcertificaterevocationlist.h>
#include <QtNetwork/private/qsslsocket_openssl_symbols_p.h>
#include <QtNetwork/private/qsslcertificaterevocationlist_p.h>
#include <QtCore/private/qmutexpool_p.h>

/*!
    \class QSslCertificateRevocationList
    \brief The QSslCertificateRevocationList class provides...
    \since 5.10

    \reentrant
    \ingroup network
    \ingroup ssl
    \ingroup shared
    \inmodule QtNetwork

    QSslCertificateRevocationList stores the list of X509 certificates revoked
    by the issuing Certificate Authority (CA). These are certificates revoked
    before their expiration date, for a number of reasons, key, attribute
    authority, or CA compromise, affiliation changed, superseded certificate,
    cessation of operation, certificate placed on hold, or privilege withdrawn.

    You can construct a certificate revocation list (CRL) from a DER (binary)
    or PEM (Base64) encoded file using the QIODevice or QByteArray constructors.
    You can also construct a null CRL, and populate it from scratch, by calling
    the various setters.

    You can call isNull() to check if your CRL is null.  You can call isValid()
    to see if your CRL has been properly signed by the issuing CA. By default,
    QSslCertificateRevocationList constructs a null CRL. A null CRL is invalid,
    but an invalid CRL is not necessarily null. If you want to reset all
    contents in a CRL, call clear().

    After loading a CRL, you can find information about the CRL, and its issuer,
    by calling one of the many accessor functions, including crlNumber(),
    version(), and issuerInfo(), among others. You can call lastUpdate() and
    nextUpdate() to check when the CRL was last updated and when it will be
    updated next. The signature() function returns the CRL's CA signature as a
    QByteArray. You can call issuerInfo() to get detailed information about the
    CRL issuer.

    Internally, QSslCertificateRevocationList is stored as an X509 structure.
    You can access this handle by calling handle(), but the results are
    likely to not be portable.

    To generate a new CRL you would do the following:

    \snippet code/src_network_ssl_qsslcertificaterevocationlist.cpp 0

    To add additional revoked certificates to an existing CRL:

    \snippet code/src_network_ssl_qsslcertificaterevocationlist.cpp 1

    To remove revoked certificates that are more than a month old from an
    existing CRL:

    \snippet code/src_network_ssl_qsslcertificaterevocationlist.cpp 2

    To remove a list of revoked certificates by serial number from an existing CRL:

    \snippet code/src_network_ssl_qsslcertificaterevocationlist.cpp 3

    To verify a certificate:

    \snippet code/src_network_ssl_qsslcertificaterevocationlist.cpp 4

    To print the issuer information:

    \snippet code/src_network_ssl_qsslcertificaterevocationlist.cpp 5

    See \l crlcreator example for how to work with CRLs.

    \sa QSslCertificate, QSslSocket, QSslKey, QSslCipher, QSslError
 */

QT_BEGIN_NAMESPACE

/*!
    Constructs a null certificate revocation list
 */
QSslCertificateRevocationList::QSslCertificateRevocationList()
        : d(new QSslCertificateRevocationListPrivate)
{
#ifndef QT_NO_OPENSSL
    d->x509Crl = q_X509_CRL_new();
#endif
}

/*!
    Constructs a QSslCertificateRevocationList by reading \a
    format encoded data from \a device. You can later call
    isNull() to see if \a device contained a certificate
    revocation list, and if this certificate revocation
    list was loaded successfully.
*/
QSslCertificateRevocationList::QSslCertificateRevocationList(QIODevice *device,
        QSsl::EncodingFormat format)
        : d(new QSslCertificateRevocationListPrivate)
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    if (device) {
        d->init(device->readAll(), format);
    }
}

/*!
    Constructs a QSslCertificateRevocationList by parsing the
    \a format encoded \a data. You can later call isNull() to
    see if \a data contained a certificate revocation list,
    and if this certificate revocation list was loaded
    successfully.
*/
QSslCertificateRevocationList::QSslCertificateRevocationList(const QByteArray &data,
        QSsl::EncodingFormat format)
        : d(new QSslCertificateRevocationListPrivate)
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    d->init(data, format);
}

/*!
    Constructs an identical copy of \a other.
*/
QSslCertificateRevocationList::QSslCertificateRevocationList(const QSslCertificateRevocationList &other)
        : d(other.d)
{
}

/*!
    Destroys the QSslCertificateRevocationList.
*/
QSslCertificateRevocationList::~QSslCertificateRevocationList()
{
}

/*!
    Copies the contents of \a other into this certificate
    revocation list, making the two certificate revocation
    list identical.
*/
QSslCertificateRevocationList &QSslCertificateRevocationList::operator=(
        const QSslCertificateRevocationList &other)
{
    d = other.d;

    return *this;
}

bool QSslCertificateRevocationList::operator==(const QSslCertificateRevocationList &other) const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    if (d == other.d || (d->null && other.d->null)) {
        return true;
#ifndef QT_NO_OPENSSL
    } else if (d->x509Crl && other.d->x509Crl) {
        return q_X509_CRL_match(d->x509Crl, other.d->x509Crl) == 0;
#endif
    }

    return false;
}

/*!
    Add additional certificates from \a revocationCertificates
    to an existing certificate revocation list. Pass a QSslError
    object to check for errors.
 */
void QSslCertificateRevocationList::addRevokedCertificates(
        const QList<QSslCertificate> &certificatesToRevoke, QSslError *sslError) const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    d->addRevokedCertificates(certificatesToRevoke, sslError);
}

/*!
    Clears the contents of this certificate revocation list,
    making it a null certificate revocation list.

    \sa isNull()
*/
void QSslCertificateRevocationList::clear()
{
    if (isNull()) {
        return;
    }

    d = new QSslCertificateRevocationListPrivate;
}

/*!
    Sets the certificate revocation list number.
 */
QByteArray QSslCertificateRevocationList::crlNumber() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->crlNumber();
}

/*!
    Returns a list containing the X509 extensions of this certificate revocation list.
 */
QList<QSslCertificateExtension> QSslCertificateRevocationList::extensions() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->extensions();
}

/*!
    Generates the new certificate revocation list with revoked certificates
    from \a revocationCertificates. Call this after calling, at a minimum,
    setCertificateAuthority() and setCrlNumber(). Pass a QSslError
    object to check for errors.

    \note You can only sign certificate revocation lists with either
    RSA or DSA keys. Also, make sure you choose the right signature
    algorithm for the key that is being used. When signing with a
    DSA key you can only choose dsaWithSHA1. RSA can use the rest,
    but not dsaWithSHA1.
 */
void QSslCertificateRevocationList::generateCertificateRevocationList(
        const QList<QSslCertificate> &certificatesToRevoke, QSslError *sslError) const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    d->generateCertificateRevocationList(certificatesToRevoke, sslError);
}

/*!
    Returns a pointer to the native certificate revocation list handle,
    if there is one, or a null pointer otherwise.

    You can use this handle, together with the native API, to access
    extended information about the certificate revocation list.

    \warning Use of this function has a high probability of being
    non-portable, and its return value may vary from platform to
    platform or change from minor release to minor release.
 */
Qt::HANDLE QSslCertificateRevocationList::handle() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->handle();
}

/*!
    Returns \c true if this is a null certificate revocation list
    (i.e., a certificate revocation list with no contents);
    otherwise returns \c false.

    By default, QSslCertificateRevocationList constructs a
    null certificate revocation list.

    \sa clear()
 */
bool QSslCertificateRevocationList::isNull() const
{
    return d->null;
}

/*!
    Returns the issuer information from the certificate revocation list.
 */
QMap<QByteArray, QString> QSslCertificateRevocationList::issuerInfo() const
{
    return d->issuerInfo();
}

/*!
    Returns \c true if this is a valid certificate revocation list
    (i.e., a certificate revocation list that has been varified
    by the Certificate Authority); otherwise returns \c false.
 */
bool QSslCertificateRevocationList::isValid() const
{
    return d->valid;
}

/*!
    Returns the date-time that the certificate revocation list
    was last updated, or an empty QDateTime if this is a null
    certificate revocation list.

  \sa nextUpdate()
 */
QDateTime QSslCertificateRevocationList::lastUpdate() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->lastUpdate();
}

/*!
    Returns the date-time that the certificate revocation list
    expires, or an empty QDateTime if this is a null certificate
    revocation list.

    \sa effectiveDate()
 */
QDateTime QSslCertificateRevocationList::nextUpdate() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->nextUpdate();
}

/*!
    Removes revoked certificates with a revocation date before
    \a dateTime from the certificate revocation list. Pass a
    QSslError object to check for errors.
 */
void QSslCertificateRevocationList::removeRevokedCertificates(
        const QDateTime &dateTime, QSslError *sslError) const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    d->removeRevokedCertificates(dateTime, sslError);
}

/*!
    Removes revoked certificates by serial number from the
    certificate revocation list. Pass a QSslError object
    to check for errors.
 */
void QSslCertificateRevocationList::removeRevokedCertificates(
        const QList<QSslRevokedCertificate> &certificatesToRemove, QSslError *sslError) const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    d->removeRevokedCertificates(certificatesToRemove, sslError);
}

/*!
    Returns a list containing the revoked certificates
    in this certificate revocation list.
 */
QList<QSslRevokedCertificate> QSslCertificateRevocationList::revokedCertificates() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->revokedCertificates();
}

/*!
    Sets the Certificate Authority certificate that will
    be used to sign new certificate revocation list.
 */
void QSslCertificateRevocationList::setCertificateAuthority(QSslCertificate *certificate,
        const QSslKey &key) const
{
    if (d->certificateAuthorityCertificate) {
        delete d->certificateAuthorityCertificate;
    }

    d->certificateAuthorityCertificate = certificate;
    d->certificateAuthorityKey = key;
}

/*!
    Sets the certificate revocation list number.
 */
void QSslCertificateRevocationList::setCrlNumber(const QByteArray &crlNumber) const
{
    d->m_crlNumber = crlNumber;
}

/*!
    Sets how long the new certificate revocation
    list will be valid for.
 */
void QSslCertificateRevocationList::setDuration(qint32 hours) const
{
    d->hours = hours;
}

/*!
    Sets the signature algorithm that will be used to sign
    the certificate revocation list.
 */
void QSslCertificateRevocationList::setSignatureAlgorithm(
        QSsl::SignatureAlgorithm signatureAlgorithm) const
{
    d->m_signatureAlgorithm = signatureAlgorithm;
}

/*!
    Returns the signature of the certificate revocation list.
 */
QByteArray QSslCertificateRevocationList::signature() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->signature();
}

/*!
    Returns the signature algorithm of the certificate revocation list.
 */
QSsl::SignatureAlgorithm QSslCertificateRevocationList::signatureAlgorithm() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->signatureAlgorithm();
}

/*!
    Returns this certificate revocation list converted to a
    DER (binary) encoded representation.
 */
QByteArray QSslCertificateRevocationList::toDer() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->toDer();
}

/*!
    Returns this certificate revocation list converted to a
    PEM (Base64) encoded representation.
 */
QByteArray QSslCertificateRevocationList::toPem() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->toPem();
}

/*!
    Returns this certificate revocation list converted to a
    human-readable text representation.
 */
QString QSslCertificateRevocationList::toText() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->toText();
}

/*!
    Verifies a certificate revocation list. The CA chain to be verified with is passed in the
    \a caCertificates parameter. Pass a QSslError object to check for errors.
 */
void QSslCertificateRevocationList::verify(
        const QList<QSslCertificate> &caCertificates, QSslError *sslError) const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    d->verify(caCertificates, sslError);
}

/*!
    Returns the certificate revocation list's version string.
 */
QByteArray QSslCertificateRevocationList::version() const
{
    QMutexLocker lock(QMutexPool::globalInstanceGet(d.data()));

    return d->version();
}

/*!
    \internal
 */
QSslCertificateRevocationListPrivate::QSslCertificateRevocationListPrivate()
{
    /*
     * Used to map the NID's to the correct
     * SignatureAlgorithm enum value
     */
    nidToSigAlgorithm.append(md2WithRSAEncryptionNid);
    nidToSigAlgorithm.append(md4WithRSAEncryptionNid);
    nidToSigAlgorithm.append(md5WithRSAEncryptionNid);
    nidToSigAlgorithm.append(shaWithRSAEncryptionNid);
    nidToSigAlgorithm.append(sha1WithRSAEncryptionNid);
    nidToSigAlgorithm.append(dsaWithSHA1Nid);
    nidToSigAlgorithm.append(sha224WithRSAEncryptionNid);
    nidToSigAlgorithm.append(sha256WithRSAEncryptionNid);
    nidToSigAlgorithm.append(sha384WithRSAEncryptionNid);
    nidToSigAlgorithm.append(sha512WithRSAEncryptionNid);
    nidToSigAlgorithm.append(mdc2WithRSANid);
    nidToSigAlgorithm.append(ripemd160WithRSANid);

    QSslSocketPrivate::ensureInitialized();
#ifndef QT_NO_OPENSSL
    q_SSL_load_error_strings();
#endif
}

/*!
    \internal
 */
QSslCertificateRevocationListPrivate::~QSslCertificateRevocationListPrivate()
{
#ifndef QT_NO_OPENSSL
    if (x509Crl) {
        q_X509_CRL_free(x509Crl);
    }
#endif
}

/*!
    \internal
 */
void QSslCertificateRevocationListPrivate::init(const QByteArray &data, QSsl::EncodingFormat format)
{
    if (!data.isEmpty()) {
        format == QSsl::Pem ? crlFromPem(data) : crlFromDer(data);
    }
}

#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug debug, const QSslCertificateRevocationList &certificateRevocationList)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace();
    debug << "QSslCertificateRevocationList(Version: "
          << certificateRevocationList.version()
#ifndef QT_NO_DATESTRING
          << ", Last Update: " << certificateRevocationList.lastUpdate()
          << ", Next Update: " << certificateRevocationList.nextUpdate()
#endif
          << ", CRL Number: " << certificateRevocationList.crlNumber()
          << ", Signature Algorithm: " << certificateRevocationList.signatureAlgorithm()
          << ", Signature: " << certificateRevocationList.signature()
          << ')';
    return debug;
}

#endif

QT_END_NAMESPACE

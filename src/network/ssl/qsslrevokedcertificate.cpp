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

#include "qsslrevokedcertificate.h"
#include "qsslrevokedcertificate_p.h"

#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

QT_BEGIN_NAMESPACE

/*!
    \class QSslRevokedCertificate
    \brief The QSslRevokedCertificate class represents an SSL revoked certificate.
    \since TBD

    \reentrant
    \ingroup network
    \ingroup ssl
    \ingroup shared
    \inmodule QtNetwork

    QSslRevokedCertificate stores the serial number and revocation date
    of a revoked certificate.

    \sa QSslCertificateRevokationList
*/

/*!
    Constructs an empty QSslRevokedCertificate object.
*/
QSslRevokedCertificate::QSslRevokedCertificate()
    : d(new QSslRevokedCertificatePrivate)
{
}

/*!
    Constructs a QSslRevokedCertificate object with the serial number and
    revocation date set.
 */
QSslRevokedCertificate::QSslRevokedCertificate(const QByteArray &serialNumber, const QDateTime &revocationDate)
    : d(new QSslRevokedCertificatePrivate)
{
    d->isNull = false;
    d->serialNumber = serialNumber;
    d->revocationDate = revocationDate;
}

/*!
    Constructs an identical copy of the \a other.
*/
QSslRevokedCertificate::QSslRevokedCertificate(const QSslRevokedCertificate &other)
    : d(new QSslRevokedCertificatePrivate)
{
    *d.data() = *other.d.data();
}

/*!
    Destroys the QSslRevokedCertificate object.
*/
QSslRevokedCertificate::~QSslRevokedCertificate()
{
}

/*!
    Copies the contents of \a other into this revoked certificate,
    making the two revoked certificates identical.
*/
QSslRevokedCertificate &QSslRevokedCertificate::operator=(const QSslRevokedCertificate &other)
{
    *d.data() = *other.d.data();
    return *this;
}

/*!
    \fn void QSslRevokedCertificate::swap(QSslRevokedCertificate &other)

    Swaps this revoked instance with \a other. This function is very
    fast and never fails.
*/

/*!
    Returns \c true if this revoked certificate is the same as
    \a other; otherwise, false is returned.
*/
bool QSslRevokedCertificate::operator==(const QSslRevokedCertificate &other) const
{
    return d->serialNumber == other.d->serialNumber && d->revocationDate == other.d->revocationDate;
}

/*!
    \fn bool QSslRevokedCertificate::operator!=(const QSslRevokedCertificate &other) const

    Returns \c true if this revoked certificate is not the same as
    \a other; otherwise, false is returned.
*/

/*!
    Returns \c true if this is a null revoked certificate;
    otherwise returns \c false.
*/
bool QSslRevokedCertificate::isNull() const
{
    return d->isNull;
}

/*!
    Returns the serial number of the revoked certificate, or an empty
    QByteArray if this is a null revoked certificate.

    \sa isNull()
*/
QByteArray QSslRevokedCertificate::serialNumber() const
{
    return d->serialNumber;
}

/*!
    Returns the revocation date of the revoked certificate.

    \sa usedBits()
*/
QDateTime QSslRevokedCertificate::revocationDate()const
{
    return d->revocationDate;
}

/*!
    Sets the serial number of the revoked certificate.
 */
void QSslRevokedCertificate::setSerialNumber(const QByteArray &serialNumber) const
{
    if (!serialNumber.isEmpty()) {
        d->serialNumber = serialNumber;

        if (d->revocationDate.isValid()) {
            d->isNull = false;
        }
    }
}

/*!
    Sets the revocation date of the revoked certificate.
 */
void QSslRevokedCertificate::setRevocationDate(const QDateTime &revocationDate) const
{
    if (revocationDate.isValid()) {
        d->revocationDate = revocationDate;

        if (!d->serialNumber.isEmpty()) {
            d->isNull = false;
        }
    }
}

QSslRevokedCertificatePrivate::QSslRevokedCertificatePrivate()
{
}

QSslRevokedCertificatePrivate::~QSslRevokedCertificatePrivate()
{
}

#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug debug, const QSslRevokedCertificate &revokedCertificate)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace().noquote();
    debug << "QSslRevokedCertificate(Serial Number=" << revokedCertificate.serialNumber()
          << ", Revokation Date=" << revokedCertificate.revocationDate()
          << ')';
    return debug;
}
#endif

QT_END_NAMESPACE

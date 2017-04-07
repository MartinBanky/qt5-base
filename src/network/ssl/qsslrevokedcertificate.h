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

#ifndef QSSLREVOKEDCERTIFICATE_H
#define QSSLREVOKEDCERTIFICATE_H

#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qscopedpointer.h>
#include <QtCore/qnamespace.h>
#include <QtCore/qmetatype.h>
#include <QtCore/qdatetime.h>

QT_BEGIN_NAMESPACE

#ifndef QT_NO_SSL

class QSslRevokedCertificatePrivate;

class Q_NETWORK_EXPORT QSslRevokedCertificate
{
public:
    QSslRevokedCertificate();
    explicit QSslRevokedCertificate(const QByteArray &serialNumber, const QDateTime &revocationDate);
    QSslRevokedCertificate(const QSslRevokedCertificate &other);
#ifdef Q_COMPILER_RVALUE_REFS
    QSslRevokedCertificate &operator=(QSslRevokedCertificate &&other) Q_DECL_NOTHROW
    { swap(other); return *this; }
#endif
    QSslRevokedCertificate &operator=(const QSslRevokedCertificate &other);
    ~QSslRevokedCertificate();

    void swap(QSslRevokedCertificate &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    bool operator==(const QSslRevokedCertificate &other) const;
    inline bool operator!=(const QSslRevokedCertificate &other) const { return !operator==(other); }

    void setSerialNumber(const QByteArray &serialNumber) const;
    void setRevocationDate(const QDateTime &revocationDate) const;

    bool isNull() const;
    QByteArray serialNumber() const;
    QDateTime revocationDate() const;

private:
    QScopedPointer<QSslRevokedCertificatePrivate> d;

    friend class QSslCertificateRevocationList;
    friend class QSslCertificateRevocationListPrivate;
};

Q_DECLARE_SHARED(QSslRevokedCertificate)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const QSslRevokedCertificate &cipher);
#endif

#endif // QT_NO_SSL

QT_END_NAMESPACE

Q_DECLARE_METATYPE(QSslRevokedCertificate)

#endif // QSSLREVOKEDCERTIFICATE_H

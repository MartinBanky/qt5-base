/****************************************************************************
**
** Copyright (C) 2017 Martin Banky <martin.banky@gmail.com>
** Contact: https://www.qt.io/licensing/
**
** This file is part of the examples of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:BSD$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** BSD License Usage
** Alternatively, you may use this file under the terms of the BSD license
** as follows:
**
** "Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**   * Redistributions of source code must retain the above copyright
**     notice, this list of conditions and the following disclaimer.
**   * Redistributions in binary form must reproduce the above copyright
**     notice, this list of conditions and the following disclaimer in
**     the documentation and/or other materials provided with the
**     distribution.
**   * Neither the name of The Qt Company Ltd nor the names of its
**     contributors may be used to endorse or promote products derived
**     from this software without specific prior written permission.
**
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
**
** $QT_END_LICENSE$
**
****************************************************************************/

#ifndef CERTIFICATECREATOR_H
#define CERTIFICATECREATOR_H

#include <QObject>
#include <QSslKey>
#include <QSslCertificate>

class QSslCertificateExtension;

class CertificateCreator : public QObject
{
    Q_OBJECT

public:
    explicit CertificateCreator(QObject *parent = 0);
    virtual ~CertificateCreator();

    void createChainCertificate(const QSslCertificate *rootCertificate,
        const QSslCertificate *intermediateCertificate, const QString &fileName) const;
    void encryptKey(const QSslKey &sslKey, const QString &fileName, const QByteArray &passphrase = QByteArray()) const;
    void saveCertificate(const QSslCertificate *certificate, const QString &fileName) const;

    void createCertificate(const QSslCertificate *certificate, qint32 days, const QSslKey &privateKey,
            const QSsl::SignatureAlgorithm &signatureAlgorithm,
            const QByteArray &country, const QByteArray &state, const QByteArray &location,
            const QByteArray &organization, const QByteArray &organizationUnit,
            const QByteArray &commonName, const QByteArray &distinguishedNameQualifier,
            const QByteArray subjectSerialNumber, const QByteArray &emailAddress,
            const QList<QSslCertificateExtension> &extensionsList, bool selfSign = false,
            QSslCertificate *caCertificate = new QSslCertificate(),
            const QSslKey &caKey = QSslKey()) const;
    void createExtension(QSslCertificateExtension &extension, qint32 nid, const QByteArray &nidValue) const;
    void createPrivateKey(const QSslKey &privateKey, qint32 bitSize) const;

private:
    CertificateCreator(const CertificateCreator&);
    CertificateCreator& operator=(const CertificateCreator&);
};

#endif // CERTIFICATECREATOR_H

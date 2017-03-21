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

#include <QFile>
#include <QDebug>
#include <QSslError>
#include <QSslCertificateExtension>

#include "certificatecreator.h"

CertificateCreator::CertificateCreator(QObject *parent) : QObject(parent)
{
}

CertificateCreator::~CertificateCreator()
{
}

void CertificateCreator::createChainCertificate(const QSslCertificate rootCertificate,
        const QSslCertificate intermediateCertificate, const QString fileName) const
{
    QByteArray certificateData = rootCertificate.toPem();
    certificateData.append(intermediateCertificate.toPem());

    QFile file(fileName);

    if (file.open(QIODevice::WriteOnly)) {
        file.write(certificateData);
        file.close();
    } else {
        qWarning("Error saving chain certificate");
    }

}

QSslCertificate *CertificateCreator::createCertificate(qint32 days, const QSslKey &privateKey,
        const QSslCertificate::SignatureAlgorithm signatureAlgorithm,
        const QByteArray &country, const QByteArray &state, const QByteArray &location,
        const QByteArray &organization, const QByteArray &organizationUnit,
        const QByteArray &commonName, const QByteArray &emailAddress,
        QList<QSslCertificateExtension *> &extensionsList, bool selfSign,
        QSslCertificate *caCertificate, const QSslKey &caKey) const
{
    QSslCertificate *certificate(new QSslCertificate);

    certificate->setDuration(days);
    certificate->setPrivateKey(privateKey);
    certificate->setSignatureAlgorithm(signatureAlgorithm);
    certificate->setSubjectCountry(country);
    certificate->setSubjectState(state);
    certificate->setSubjectLocation(location);
    certificate->setSubjectOrginization(organization);
    certificate->setSubjectOrginizationUnit(organizationUnit);
    certificate->setSubjectCommonName(commonName);
    certificate->setSubjectEmailAddress(emailAddress);
    certificate->setX509Extensions(extensionsList);

    if (!selfSign) {
        certificate->setCertificateAuthority(caCertificate, caKey);
    }

    QSslError::SslError status  = certificate->generateCertificate();

    if (status) {
        qWarning() << "Error creating certificate. Error:" << status;
    }

    return certificate;
}

QSslCertificateExtension *CertificateCreator::createExtension(qint32 nid, const QByteArray nidValue) const
{
    QSslCertificateExtension *extension(new QSslCertificateExtension);

    extension->setNid(nid);
    extension->setNidValue(nidValue);

    return extension;
}

QSslKey *CertificateCreator::createPrivateKey(qint32 bitSize) const
{
    QSslKey *sslKey(new QSslKey);

    sslKey->setAlgorithm(QSsl::Rsa);
    sslKey->setBitSize(bitSize);
    sslKey->generatePrivateKey();

    return sslKey;
}

void CertificateCreator::encryptKey(QSslKey *sslKey, const QString fileName,
                                    const QByteArray passphrase) const
{
    QByteArray encryptedKey;

    if (!passphrase.isEmpty()) {
        sslKey->setCipher(QSslKey::Aes256Cbc);
        encryptedKey = sslKey->toPem(passphrase);
    } else {
        encryptedKey = sslKey->toPem();
    }

    QFile file(fileName);

    if (file.open(QIODevice::WriteOnly)) {
        file.write(encryptedKey);
        file.close();
    } else {
        qWarning("Error saving key");
    }
}

void CertificateCreator::saveCertificate(const QSslCertificate &certificate,
                                         const QString fileName) const
{
    const QByteArray certificateData = certificate.toPem();

    QFile file(fileName);

    if (file.open(QIODevice::WriteOnly)) {
        file.write(certificateData);
        file.close();
    } else {
        qWarning("Error saving certificate");
    }
}

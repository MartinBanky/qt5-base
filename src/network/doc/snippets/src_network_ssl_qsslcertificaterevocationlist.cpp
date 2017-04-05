/****************************************************************************
**
** Copyright (C) 2017 Martin Banky <martin.banky@gmail.com>
** Contact: https://www.qt.io/licensing/
**
** This file is part of the documentation of the Qt Toolkit.
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

//! [0]
QFile file("private/ca.key.pem");
file.open(QIODevice::ReadOnly);

const QSslKey caKey(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, "password");
file.close();

file.setFileName("certs/ca.cert.pem");
file.open(QIODevice::ReadOnly);

QSslCertificate caCertificate(file.readAll());
file.close();

QList<QSslCertificate> certificatesToRevoke(QSslCertificate::fromPath("revokedcerts/*.pem",
        QSsl::Pem, QRegExp::Wildcard));

QSslCertificateRevocationList crl;

crl.setCertificateAuthority(&caCertificate, caKey);
crl.setCrlNumber("1234567890");
crl.setDuration(24);
crl.setSignatureAlgorithm(QSsl::sha512WithRSAEncryption);

crl.generateCertificateRevocationList(certificatesToRevoke);
//! [0]

//! [1]
certificatesToRevoke = (QSslCertificate::fromPath("revokedcerts/*.pem", QSsl::Pem, QRegExp::Wildcard));

crl.setCertificateAuthority(&caCertificate, caKey);
crl.setCrlNumber("1234567891");
crl.setDuration(24);
crl.setSignatureAlgorithm(QSsl::sha512WithRSAEncryption);
crl.addRevokedCertificates(certificatesToRevoke);
//! [1]

//! [2]
const QDateTime removeBeforeDateTime(QDateTime::currentDateTimeUtc().addMonths(-1));

crl.setCertificateAuthority(&caCertificate, caKey);
crl.setCrlNumber("1234567892");
crl.setDuration(24);
crl.setSignatureAlgorithm(QSsl::sha512WithRSAEncryption);
crl.removeRevokedCertificates(removeBeforeDateTime);
//! [2]

//! [3]
crl.setCertificateAuthority(&caCertificate, caKey);
crl.setCrlNumber("1234567893");
crl.setDuration(24);
crl.setSignatureAlgorithm(QSsl::sha512WithRSAEncryption);
crl.removeRevokedCertificates(revokedCertificates);
//! [3]

//! [4]
QList<QSslCertificate> caChain;

caChain << caCertificate;
crl.verify(caChain);

if (crl.isValid()) {
    ...
}
//! [4]

//! [5]
const QMap<QByteArray, QString> issuerInfo(crl.issuerInfo());
QMapIterator<QByteArray, QString> info(issuerInfo);

while (info.hasNext()) {
    info.next();
    qDebug() << info.key() << "=" << info.value();
}
//! [5]

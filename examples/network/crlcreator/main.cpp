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

#include <QMap>
#include <QFile>
#include <QDebug>
#include <QSslKey>
#include <QThread>
#include <QSslCertificate>
#include <QCoreApplication>
#include <QSslRevokedCertificate>
#include <QSslCertificateExtension>
#include <QSslCertificateRevocationList>

#include "crlcreator.h"

void crlInfo(const QSslCertificateRevocationList crl)
{
    qDebug("Crl Number: %s", crl.crlNumber().constData());
    qDebug("Version: %s (0x%i)", crl.version().constData(), crl.version().toInt() - 1);
    qDebug("Last Update: %s GMT", crl.lastUpdate().toUTC().toString("MMM d HH:mm:ss yyyy").toLatin1().constData());
    qDebug("Next Update: %s GMT", crl.nextUpdate().toUTC().toString("MMM d HH:mm:ss yyyy").toLatin1().constData());

    QSslCertificateExtension extension;
    const QList<QSslCertificateExtension> extensions(crl.extensions());

    foreach (extension, extensions) {
        qDebug("Extension Info:");
        qDebug() << "\tName:" << extension.name();
        qDebug() << "\toid:" << extension.oid();
        qDebug() << "\tValue:" << extension.value();
        qDebug() << "\tCritical:" << extension.isCritical();
        qDebug() << "\tSupported:" << extension.isSupported() << '\n';
    }

    QSslRevokedCertificate revokedCertificate;
    const QList<QSslRevokedCertificate> revokedCertificates(crl.revokedCertificates());

    qDebug("Revoked Certificates:");

    foreach (revokedCertificate, revokedCertificates) {
        qDebug("    Serial Number: %s", revokedCertificate.serialNumber().constData());
        qDebug("        Revocation Date: %s GMT",
                revokedCertificate.revocationDate().toString("MMM d HH:mm:ss yyyy").toLatin1().constData());
    }

    switch (crl.signatureAlgorithm()) {
    case QSsl::md2WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::md4WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::md5WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::shaWithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::sha1WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::dsaWithSHA1:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::sha224WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::sha256WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::sha384WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::sha512WithRSAEncryption:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::mdc2WithRSA:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    case QSsl::ripemd160WithRSA:
        qDebug() << "    Signature Algorithm: md2WithRSAEncryption";
        break;
    }

    const QByteArray rawSignature(crl.signature());
    QByteArray signature("         ");

    for (qint32 i = 0, j = 3; i < rawSignature.size(); ++i, j += 3) {
        signature.append(rawSignature.at(i));
        signature.append(rawSignature.at(++i));
        signature.append(':');

        if (j == 54) {
            signature.append("\n         ");
            j = 0;
        }
    }

    qDebug("%s", signature.constData());
}

int main(int argc, char *argv[])
{
    Q_UNUSED(argc)
    Q_UNUSED(argv)

    QFile file("private/intermediate.key.pem");
    file.open(QIODevice::ReadOnly);

    const QSslKey caKey(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, "intermediate-password");
    file.close();

    file.setFileName("certs/intermediate.cert.pem");
    file.open(QIODevice::ReadOnly);

    QSslCertificate caCertificate(file.readAll());
    file.close();

    QList<QSslCertificate> certificatesToRevoke(QSslCertificate::fromPath("revokedcerts/*.pem",
            QSsl::Pem, QRegExp::Wildcard));

    if (certificatesToRevoke.isEmpty()) {
        return 0;
    }

    QSslCertificateRevocationList crl;

    crl.setCertificateAuthority(&caCertificate, caKey);
    crl.setCrlNumber("1234567890");
    crl.setDuration(24);
    crl.setSignatureAlgorithm(QSsl::sha512WithRSAEncryption);

    crl.generateCertificateRevocationList(certificatesToRevoke);

    QByteArray crlData(crl.toPem());

    file.setFileName("crl/intermediate.crl.pem");
    file.open(QIODevice::WriteOnly);
    file.write(crlData);
    file.close();

    crlData = crl.toDer();

    file.setFileName("crl/intermediate.crl.der");
    file.open(QIODevice::WriteOnly);
    file.write(crlData);
    file.close();

    const QString crlString = crl.toText();

    file.setFileName("crl/intermediate.crl.txt");
    file.open(QIODevice::WriteOnly);
    file.write(crlString.toLatin1());
    file.close();

    qDebug("\n##########  Generated CRL  ##########");
    crlInfo(crl);
    qDebug("##########  Generated CRL  ##########\n");

    QList<QSslCertificate> caChain;

    caChain << caCertificate;
    crl.verify(caChain);

    qDebug("##########  Certificate Validation  ##########");
    qDebug() << "Valid Certificate:" << crl.isValid();
    qDebug("##########  Certificate Validation  ##########\n");

    const QMap<QByteArray, QString> issuerInfo(crl.issuerInfo());
    QMapIterator<QByteArray, QString> info(issuerInfo);

    qDebug("##########  Issuer Information  ##########");
    while (info.hasNext()) {
        info.next();
        qDebug("%s=%s", info.key().constData(), info.value().toLatin1().constData());
    }
    qDebug("##########  Issuer Information  ##########\n");

    certificatesToRevoke = (QSslCertificate::fromPath("addrevokedcerts/*.pem",
            QSsl::Pem, QRegExp::Wildcard));

    if (certificatesToRevoke.isEmpty()) {
        return 0;
    }

    file.setFileName("crl/intermediate.crl.add.pem");
    file.open(QIODevice::ReadOnly);

    QSslCertificateRevocationList crlAddRevs(file.readAll());
    file.close();

    // For use by Remove Revoked Certificates CRL
    const QList<QSslRevokedCertificate> revokedCertificates(crlAddRevs.revokedCertificates());

    crlAddRevs.setCertificateAuthority(&caCertificate, caKey);
    crlAddRevs.setCrlNumber("1234567891");
    crlAddRevs.setDuration(24);
    crlAddRevs.setSignatureAlgorithm(QSsl::sha512WithRSAEncryption);
    crlAddRevs.addRevokedCertificates(certificatesToRevoke);

    crlData = crlAddRevs.toPem();

    file.setFileName("crl/intermediate.crl.add.new.pem");
    file.open(QIODevice::WriteOnly);
    file.write(crlData);
    file.close();

    qDebug("\n##########  Added Revocations  ##########");
    crlInfo(crlAddRevs);
    qDebug("##########  Added Revocations  ##########\n");

    QSslCertificateRevocationList crlRemoveRevsByRevs(crlAddRevs);
    QSslCertificateRevocationList crlRemoveRevsByDateTime(crlAddRevs);

    const QDateTime removeBeforeDateTime(QDateTime::currentDateTimeUtc().addMonths(-1));

    crlRemoveRevsByDateTime.setCrlNumber("1234567892");
    crlRemoveRevsByDateTime.removeRevokedCertificates(removeBeforeDateTime);

    qDebug("\n##########  Remove Before DateTime CRL  ##########");
    crlInfo(crlRemoveRevsByDateTime);
    qDebug("##########  Remove Before DateTime CRL  ##########\n");

    crlRemoveRevsByRevs.setCrlNumber("1234567893");
    crlRemoveRevsByRevs.removeRevokedCertificates(revokedCertificates);

    qDebug("\n##########  Remove Revoked Certificates CRL  ##########");
    crlInfo(crlRemoveRevsByRevs);
    qDebug("##########  Remove Revoked Certificates CRL  ##########");

    file.setFileName("crl/intermediate.crl.add.new.pem");
    file.open(QIODevice::ReadOnly);

    const QSslCertificateRevocationList existingPemCrl(file.readAll());
    file.close();

    qDebug("\n##########  Opened PEM CRL  ##########");
    crlInfo(existingPemCrl);

    file.setFileName("crl/intermediate.crl.der");
    file.open(QIODevice::ReadOnly);

    const QSslCertificateRevocationList existingDerCrl(file.readAll(), QSsl::Der);
    file.close();

    qDebug("\n##########  Opened DER CRL  ##########");
    crlInfo(existingDerCrl);

    return 1;
}

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

#include <QSslKey>
#include <QSslCertificate>
#include <QCoreApplication>
#include <QSslCertificateExtension>

// Good source for NID information
#include <openssl/obj_mac.h>

#include "certificatecreator.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    CertificateCreator certificateServer;

    // Create the Root Certificate Authority key
    QSslKey caKey;

    certificateServer.createPrivateKey(caKey, 4096);
    certificateServer.encryptKey(caKey, "ca.key.pem", "ca-password");

    QSslCertificateExtension subjectKeyIdentifierExt;
    QSslCertificateExtension authorityKeyIdentifierExt;
    QSslCertificateExtension basicConstraintsExt;
    QSslCertificateExtension keyUsageExt;

    certificateServer.createExtension(subjectKeyIdentifierExt, NID_subject_key_identifier, "hash");
    certificateServer.createExtension(authorityKeyIdentifierExt, NID_authority_key_identifier, "keyid:always");
    certificateServer.createExtension(basicConstraintsExt, NID_basic_constraints, "critical, CA:true");
    certificateServer.createExtension(keyUsageExt, NID_key_usage, "critical, digitalSignature, cRLSign, keyCertSign");

    QList<QSslCertificateExtension> extensions;

    extensions.append(subjectKeyIdentifierExt);
    extensions.append(authorityKeyIdentifierExt);
    extensions.append(basicConstraintsExt);
    extensions.append(keyUsageExt);

    // Create Root Certificate Authority certificate
    QSslCertificate *caCertificate(new QSslCertificate);

    // Set duration to 20 years
    certificateServer.createCertificate(caCertificate, 7305, caKey, QSsl::sha512WithRSAEncryption,
            "US", "AZ", "Tucson", "SSL Test Server", "SSL Test Server Certificate Authority",
            "SSL Test Server Root CA", QDateTime::currentDateTime().toString("yyyyMMddHHmmsszzz,").toLatin1(),
            "1234567890", "admin@ssltestserver.org", extensions, true);
    certificateServer.saveCertificate(caCertificate, "ca.cert.pem");

    // Create the Intermdiate Certificate Authority key
    QSslKey caIntermediateKey;

    certificateServer.createPrivateKey(caIntermediateKey, 2048);
    certificateServer.encryptKey(caIntermediateKey, "intermediate.key.pem", "intermediate-password");

    certificateServer.createExtension(extensions[2], NID_basic_constraints, "critical, CA:true, pathlen:0");

    // Create Intermdiate Certificate Authority certificate
    QSslCertificate *intermdiateCertificate(new QSslCertificate);

    // Set duration to 10 years
    certificateServer.createCertificate(intermdiateCertificate, 3650, caIntermediateKey,
            QSsl::sha512WithRSAEncryption, "US", "AZ", "Tucson", "SSL Test Server",
            "SSL Test Server Certificate Authority", "SSL Test Server Intermediate CA",
            QDateTime::currentDateTime().toString("yyyyMMddHHmmsszzz,").toLatin1(),
            "1234567890", "admin@ssltestserver.org", extensions, false, caCertificate, caKey);
    certificateServer.saveCertificate(intermdiateCertificate, "intermediate.cert.pem");

    // Certificate chain. Install on client systems to have the new Certificate Authority recognized by the browser
    certificateServer.createChainCertificate(caCertificate, intermdiateCertificate, "ca-chain.cert.pem");

    // Create the client web server key
    QSslKey webServerKey;

    certificateServer.createPrivateKey(webServerKey, 2048);
    certificateServer.encryptKey(webServerKey, "server.ssltestserver.org.key.pem");

    QSslCertificateExtension netscapeCertTypeExt;
    QSslCertificateExtension netscapeCommentExt;
    QSslCertificateExtension crlDistributionPointsExt;

    certificateServer.createExtension(basicConstraintsExt, NID_basic_constraints, "CA:FALSE");
    certificateServer.createExtension(netscapeCertTypeExt, NID_netscape_cert_type, "client, email");
    certificateServer.createExtension(netscapeCommentExt, NID_netscape_comment, "OpenSSL Generated Client Certificate");
    certificateServer.createExtension(subjectKeyIdentifierExt, NID_subject_key_identifier, "hash");
    certificateServer.createExtension(authorityKeyIdentifierExt, NID_authority_key_identifier, "keyid:always");
    certificateServer.createExtension(keyUsageExt, NID_key_usage, "critical, nonRepudiation, digitalSignature, keyEncipherment");
    certificateServer.createExtension(crlDistributionPointsExt, NID_crl_distribution_points, "URI:http://server.ssltestserver.org/certs/intermediate.crl.pem");

    extensions.clear();

    extensions.append(basicConstraintsExt);
    extensions.append(netscapeCertTypeExt);
    extensions.append(netscapeCommentExt);
    extensions.append(subjectKeyIdentifierExt);
    extensions.append(authorityKeyIdentifierExt);
    extensions.append(keyUsageExt);
    extensions.append(crlDistributionPointsExt);

    // Create client web server certificate
    QSslCertificate *webServerCertificate(new QSslCertificate);

    // Set duration to 375 days. Give them a 10 day grace period.
    certificateServer.createCertificate(webServerCertificate, 375, caIntermediateKey,
            QSsl::sha512WithRSAEncryption, "US", "AZ", "Tucson", "SSL Test Server",
            "SSL Test Server Web Services", "server.ssltestserver.org",
            QDateTime::currentDateTime().toString("yyyyMMddHHmmsszzz,").toLatin1(),
            "1234567890", "admin@ssltestserver.org", extensions, false, caCertificate, caKey);
    certificateServer.saveCertificate(webServerCertificate, "server.ssltestserver.org.cert.pem");

    // Create a Subject Alternative Name (SAN) server key
    QSslKey sanServerKey;

    certificateServer.createPrivateKey(sanServerKey, 2048);
    certificateServer.encryptKey(sanServerKey, "san.ssltestserver.org.key.pem");

    QSslCertificateExtension subjectAltName;

    certificateServer.createExtension(subjectAltName, NID_subject_alt_name, "DNS:server0.ssltestserver.org,"
                                                                            "DNS:server1.ssltestserver.org,"
                                                                            "DNS:server2.ssltestserver.org,"
                                                                            "DNS:server3.ssltestserver.org,"
                                                                            "DNS:server4.ssltestserver.org");

    extensions.append(subjectAltName);

    // Create SAN server certificate
    QSslCertificate *sanServerCertificate(new QSslCertificate);

    // Set duration to 375 days. Give them a 10 day grace period.
    certificateServer.createCertificate(sanServerCertificate, 3650, caIntermediateKey,
            QSsl::sha512WithRSAEncryption, "US", "AZ", "Tucson", "SSL Test Server",
            "SSL Test Server SAN Services", "san.ssltestserver.org",
            QDateTime::currentDateTime().toString("yyyyMMddHHmmsszzz,").toLatin1(),
            "1234567890", "admin@ssltestserver.org", extensions, false, caCertificate, caKey);
    certificateServer.saveCertificate(sanServerCertificate, "san.ssltestserver.org.cert.pem");

    return 1;
}

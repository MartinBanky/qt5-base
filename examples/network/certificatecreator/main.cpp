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
    QSslKey *caKey(new QSslKey);

    caKey = certificateServer.createPrivateKey(4096);
    certificateServer.encryptKey(caKey, "ca.key.pem", "ca-password");

    QList<QSslCertificateExtension *> extensions;

    extensions.append(certificateServer.createExtension(NID_subject_key_identifier, "hash"));
    extensions.append(certificateServer.createExtension(NID_authority_key_identifier, "keyid:always,issuer"));
    extensions.append(certificateServer.createExtension(NID_basic_constraints, "critical, CA:true"));
    extensions.append(certificateServer.createExtension(NID_key_usage, "critical, digitalSignature, cRLSign, keyCertSign"));

    // Create Root Certificate Authority certificate
    QSslCertificate *caCertificate(new QSslCertificate);

    // Set duration to 20 years
    caCertificate = certificateServer.createCertificate(7305, *caKey, QSslCertificate::sha512WithRSAEncryption,
            "US", "AZ", "Tucson", "SSL Test Server", "SSL Test Server Certificate Authority",
            "SSL Test Server Root CA", "admin@ssltestserver.org", extensions, true);
    certificateServer.saveCertificate(*caCertificate, "ca.cert.pem");

    QSslCertificateExtension *extension;

    foreach (extension, extensions) {
        delete extension;
    }

    extensions.clear();

    // Create the Intermdiate Certificate Authority key
    QSslKey *caIntermediateKey(new QSslKey);

    caIntermediateKey = certificateServer.createPrivateKey(2048);
    certificateServer.encryptKey(caIntermediateKey, "intermediate.key.pem", "intermediate-password");

    extensions.append(certificateServer.createExtension(NID_subject_key_identifier, "hash"));
    extensions.append(certificateServer.createExtension(NID_authority_key_identifier, "keyid:always,issuer"));
    extensions.append(certificateServer.createExtension(NID_basic_constraints, "critical, CA:true, pathlen:0"));
    extensions.append(certificateServer.createExtension(NID_key_usage, "critical, digitalSignature, cRLSign, keyCertSign"));

    // Create Intermdiate Certificate Authority certificate
    QSslCertificate *intermdiateCertificate(new QSslCertificate);

    // Set duration to 10 years
    intermdiateCertificate = certificateServer.createCertificate(3650, *caIntermediateKey,
            QSslCertificate::sha512WithRSAEncryption, "US", "AZ", "Tucson", "SSL Test Server",
            "SSL Test Server Certificate Authority", "SSL Test Server Intermediate CA",
            "admin@ssltestserver.org", extensions, false, caCertificate, *caKey);
    certificateServer.saveCertificate(*intermdiateCertificate, "intermediate.cert.pem");

    // Certificate chain. Install on client systems to have the new Certificate Authority recognized by the browser
    certificateServer.createChainCertificate(*caCertificate, *intermdiateCertificate, "ca-chain.cert.pem");

    foreach (extension, extensions) {
        delete extension;
    }

    extensions.clear();

    // Create the client web server key
    QSslKey *webServerKey(new QSslKey);

    webServerKey = certificateServer.createPrivateKey(2048);
    certificateServer.encryptKey(webServerKey, "server.ssltestserver.org.key.pem");

    extensions.append(certificateServer.createExtension(NID_basic_constraints, "CA:FALSE"));
    extensions.append(certificateServer.createExtension(NID_netscape_cert_type, "client, email"));
    extensions.append(certificateServer.createExtension(NID_netscape_comment, "OpenSSL Generated Client Certificate"));
    extensions.append(certificateServer.createExtension(NID_subject_key_identifier, "hash"));
    extensions.append(certificateServer.createExtension(NID_authority_key_identifier, "keyid,issuer"));
    extensions.append(certificateServer.createExtension(NID_key_usage, "critical, nonRepudiation, digitalSignature, keyEncipherment"));

    // crlDistributionPoints
    extensions.append(certificateServer.createExtension(NID_crl_distribution_points, "URI:http://server.ssltestserver.org/certs/intermediate.crl.pem"));

    // Create Intermdiate Certificate Authority certificate
    QSslCertificate *webServerCertificate(new QSslCertificate);

    // Set duration to 375 days. Give them a 10 day grace period.
    webServerCertificate = certificateServer.createCertificate(3650, *caIntermediateKey,
            QSslCertificate::sha512WithRSAEncryption, "US", "AZ", "Tucson", "SSL Test Server",
            "SSL Test Server Certificate Authority", "SSL Test Server Intermediate CA",
            "admin@ssltestserver.org", extensions, false, caCertificate, *caKey);
    certificateServer.saveCertificate(*webServerCertificate, "server.ssltestserver.org.cert.pem");

    return 1;
}

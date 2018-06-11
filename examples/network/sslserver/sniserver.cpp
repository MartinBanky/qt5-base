/****************************************************************************
**
** Copyright (C) 2018 Martin Banky <martin.banky@gmail.com>
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

#include <QSslSocket>
#include <QTextStream>
#include <QSslCertificate>

#include "sniserver.h"
#include "sslserver.h"

SniServer::SniServer(QObject *parent) : QThread(parent)
    , m_sslServer(new SslServer(this))
{
}

SniServer::~SniServer()
{
    m_sslServer->close();
}

void SniServer::run()
{
    QObject::connect(m_sslServer, &SslServer::newConnection, this, &SniServer::newSslConnection);

    QTextStream standardOutput(stdout);

    if (m_sslServer->listen(QHostAddress::Any, 443)) {
        standardOutput << QObject::tr("The SNI Https server is running on port 443") << endl;;
    } else {
        standardOutput << QObject::tr("Unable to start the Http server: %1").arg(m_sslServer->errorString()) << endl;;
    }
}

void SniServer::newSslConnection()
{
    QSslSocket *sslSocket = qobject_cast<QSslSocket *>(m_sslServer->nextPendingConnection());

    sslSocket->setServerNameIndicationModeEnabled();
    sslSocket->startServerEncryption();

    QObject::connect(sslSocket, &QSslSocket::readyRead, this, &SniServer::readInputHttps);
    QObject::connect(sslSocket, &QSslSocket::disconnected, this, &SniServer::disconnected);
    QObject::connect(sslSocket, &QSslSocket::serverNameIndicatorReady, this, &SniServer::readServerNameIndicator);

    QTextStream standardOutput(stdout);

    standardOutput << QObject::tr("SniServer Connected to: %1").arg(sslSocket->peerAddress().toString());
}

void SniServer::disconnected()
{
    QSslSocket *sslSocket(qobject_cast<QSslSocket *>(sender()));

    sslSocket->deleteLater();
    sslSocket = 0;
}

void SniServer::readInputHttps()
{
    QSslSocket *sslSocket(qobject_cast<QSslSocket *>(sender()));

    QTextStream standardOutput(stdout);

    standardOutput << QObject::tr("SniServer::readInputHttps: Reading from: %1").arg(sslSocket->peerAddress().toString()) << endl;
    standardOutput << QObject::tr("SniServer::readInputHttps: Bytes Available: %1").arg(sslSocket->bytesAvailable()) << endl;

    const QString incomingRequest(sslSocket->readAll());

    standardOutput << QObject::tr("SniServer::readInputHttps: Message: %1").arg(incomingRequest) << endl;

    sslSocket = 0;
}

void SniServer::readServerNameIndicator(const QByteArray serverNameIndicator)
{
    QSslSocket *sslSocket(qobject_cast<QSslSocket *>(sender()));

    sslSocket->setPrivateKey(serverNameIndicator + ".key.pem");
    sslSocket->setLocalCertificate(serverNameIndicator + ".cert.pem");
    sslSocket->resumeHandshake();
}

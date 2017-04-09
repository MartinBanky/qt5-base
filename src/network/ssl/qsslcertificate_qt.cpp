/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
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

#include "qsslcertificate.h"
#include "qsslcertificate_p.h"

#include "qssl_p.h"
#include "qsslkey.h"
#include "qsslkey_p.h"
#include "qsslcertificateextension.h"
#include "qsslcertificateextension_p.h"
#include "qasn1element_p.h"

#include <QtCore/qdatastream.h>

QT_BEGIN_NAMESPACE

bool QSslCertificate::operator==(const QSslCertificate &other) const
{
    if (d == other.d)
        return true;
    if (d->null && other.d->null)
        return true;
    return d->derData == other.d->derData;
}

uint qHash(const QSslCertificate &key, uint seed) Q_DECL_NOTHROW
{
    // DER is the native encoding here, so toDer() is just "return d->derData":
    return qHash(key.toDer(), seed);
}

bool QSslCertificate::isNull() const
{
    return d->null;
}

bool QSslCertificate::isSelfSigned() const
{
    if (d->null)
        return false;

    qCWarning(lcSsl,
              "QSslCertificate::isSelfSigned: This function does not check, whether the certificate "
              "is actually signed. It just checks whether issuer and subject are identical");
    return d->subjectMatchesIssuer;
}

QByteArray QSslCertificate::version() const
{
    return d->versionString;
}

QByteArray QSslCertificate::serialNumber() const
{
    return d->serialNumberString;
}

QStringList QSslCertificate::issuerInfo(SubjectInfo info) const
{
    return issuerInfo(QSslCertificatePrivate::subjectInfoToString(info));
}

QStringList QSslCertificate::issuerInfo(const QByteArray &attribute) const
{
    return d->issuerInfo.values(attribute);
}

QStringList QSslCertificate::subjectInfo(SubjectInfo info) const
{
    return subjectInfo(QSslCertificatePrivate::subjectInfoToString(info));
}

QStringList QSslCertificate::subjectInfo(const QByteArray &attribute) const
{
    return d->subjectInfo.values(attribute);
}

QList<QByteArray> QSslCertificate::subjectInfoAttributes() const
{
    return d->subjectInfo.uniqueKeys();
}

QList<QByteArray> QSslCertificate::issuerInfoAttributes() const
{
    return d->issuerInfo.uniqueKeys();
}

QMultiMap<QSsl::AlternativeNameEntryType, QString> QSslCertificate::subjectAlternativeNames() const
{
    return d->subjectAlternativeNames;
}

QDateTime QSslCertificate::effectiveDate() const
{
    return d->notValidBefore;
}

QDateTime QSslCertificate::expiryDate() const
{
    return d->notValidAfter;
}

#ifndef Q_OS_WINRT // implemented in qsslcertificate_winrt.cpp
Qt::HANDLE QSslCertificate::handle() const
{
    Q_UNIMPLEMENTED();
    return 0;
}
#endif

QSslKey QSslCertificate::publicKey() const
{
    QSslKey key;
    key.d->type = QSsl::PublicKey;
    if (d->publicKeyAlgorithm != QSsl::Opaque) {
    key.d->algorithm = d->publicKeyAlgorithm;
    key.d->decodeDer(d->publicKeyDerData);
    }
    return key;
}

QList<QSslCertificateExtension> QSslCertificate::extensions() const
{
    return d->extensions;
}

#define BEGINCERTSTRING "-----BEGIN CERTIFICATE-----"
#define ENDCERTSTRING "-----END CERTIFICATE-----"

QByteArray QSslCertificate::toPem() const
{
    QByteArray array = toDer();

    // Convert to Base64 - wrap at 64 characters.
    array = array.toBase64();
    QByteArray tmp;
    for (int i = 0; i <= array.size() - 64; i += 64) {
        tmp += QByteArray::fromRawData(array.data() + i, 64);
        tmp += '\n';
    }
    if (int remainder = array.size() % 64) {
        tmp += QByteArray::fromRawData(array.data() + array.size() - remainder, remainder);
        tmp += '\n';
    }

    return BEGINCERTSTRING "\n" + tmp + ENDCERTSTRING "\n";
}

QByteArray QSslCertificate::toDer() const
{
    return d->derData;
}

//#define ASN1_INTEGER int
//#define EVP_PKEY int
//#define BIO_write
//#define BIO_printf
//#define X509_ALGOR int
//#define ASN1_BIT_STRING QString
//#define X509_PUBKEY QSslKey
//#define i2a_ASN1_OBJECT
//#define X509_get0_tbs_sigalg(x) *int x
//#define X509_FLAG_NO_PUBKEY 0

QString QSslCertificate::toText() const
{
//    int *bp;
//    X509 *x;
//    unsigned long nmflags = 0;
//    unsigned long cflag = 0;


//    long l;
//    int ret = 0, i;
//    char *m = NULL, mlch = ' ';
//    int nmindent = 16;
//    ASN1_INTEGER *bs;
//    EVP_PKEY *pkey = NULL;
//    const char *neg;

//    // Signature algorithm
//    const X509_ALGOR *tsig_alg = X509_get0_tbs_sigalg(x);

//    if (!(cflag & X509_FLAG_NO_PUBKEY)) {
//        X509_PUBKEY *xpkey = X509_get_X509_PUBKEY(x);
//        ASN1_OBJECT *xpoid;
//        X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, xpkey);
//        if (BIO_write(bp, "        Subject Public Key Info:\n", 33) <= 0)
//            goto err;
//        if (BIO_printf(bp, "%12sPublic Key Algorithm: ", "") <= 0)
//            goto err;
//        if (i2a_ASN1_OBJECT(bp, xpoid) <= 0)
//            goto err;
//        if (BIO_puts(bp, "\n") <= 0)
//            goto err;

//        pkey = X509_get0_pubkey(x);
//        if (pkey == NULL) {
//            BIO_printf(bp, "%12sUnable to load Public Key\n", "");
//            ERR_print_errors(bp);
//        } else {
//            EVP_PKEY_print_public(bp, pkey, 16, NULL);
//        }
//    }

//    if (!(cflag & X509_FLAG_NO_IDS)) {
//        const ASN1_BIT_STRING *iuid, *suid;
//        X509_get0_uids(x, &iuid, &suid);
//        if (iuid != NULL) {
//            if (BIO_printf(bp, "%8sIssuer Unique ID: ", "") <= 0)
//                goto err;
//            if (!X509_signature_dump(bp, iuid, 12))
//                goto err;
//        }
//        if (suid != NULL) {
//            if (BIO_printf(bp, "%8sSubject Unique ID: ", "") <= 0)
//                goto err;
//            if (!X509_signature_dump(bp, suid, 12))
//                goto err;
//        }
//    }

//    if (!(cflag & X509_FLAG_NO_EXTENSIONS))
//        X509V3_extensions_print(bp, "X509v3 extensions",
//                                X509_get0_extensions(x), cflag, 8);

//    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
//        const X509_ALGOR *sig_alg;
//        const ASN1_BIT_STRING *sig;
//        X509_get0_signature(&sig, &sig_alg, x);
//        if (X509_signature_print(bp, sig_alg, sig) <= 0)
//            goto err;
//    }

//    if (!(cflag & X509_FLAG_NO_AUX)) {
//        if (!X509_aux_print(bp, x, 0))
//            goto err;
//    }

//err:


    QString cetificateText = "Certificate:\n    Data:\n        Version: ";

    cetificateText.append(d->versionString);
    cetificateText.append("        Serial Number: " + d->serialNumberString);
    cetificateText.append("    Signature Algorithm: " + QByteArray("Unknown"));
    cetificateText.append("        Issuer: ");

    QStringList info = issuerInfo(QSslCertificate::CountryName);

    if (!info.isEmpty())
        cetificateText.append("C = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::StateOrProvinceName);

    if (!info.isEmpty())
        cetificateText.append("ST = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::LocalityName);

    if (!info.isEmpty())
        cetificateText.append("L = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::Organization);

    if (!info.isEmpty())
        cetificateText.append("O = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::OrganizationalUnitName);

    if (!info.isEmpty())
        cetificateText.append("OU = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::CommonName);

    if (!info.isEmpty())
        cetificateText.append("CN = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::EmailAddress);

    if (!info.isEmpty())
        cetificateText.append("emailAddress = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::DistinguishedNameQualifier);

    if (!info.isEmpty())
        cetificateText.append("dnQualifier = " + info.at(0) + ", ");

    info = issuerInfo(QSslCertificate::SerialNumber);

    if (!info.isEmpty())
        cetificateText.append("serialNumber = " + info.at(0) + ", ");

    cetificateText.chop(2);
    cetificateText.append("\n        Validity\n            Not Before: ");

    if (d->notValidBefore.isValid())
        cetificateText.append(d->notValidBefore.toUTC().toString("MMM d HH:mm:ss yyyy") + " GMT\n");
    else
        cetificateText.append("Unknown\n");

    cetificateText.append("            Not After : ");

    if (d->notValidAfter.isValid())
        cetificateText.append(d->notValidAfter.toUTC().toString("MMM d HH:mm:ss yyyy") + " GMT\n");
    else
        cetificateText.append("Unknown\n");

    cetificateText.append("        Subject: ");

    info = subjectInfo(QSslCertificate::CountryName);

    if (!info.isEmpty())
        cetificateText.append("C = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::StateOrProvinceName);

    if (!info.isEmpty())
        cetificateText.append("ST = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::LocalityName);

    if (!info.isEmpty())
        cetificateText.append("L = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::Organization);

    if (!info.isEmpty())
        cetificateText.append("O = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::OrganizationalUnitName);

    if (!info.isEmpty())
        cetificateText.append("OU = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::CommonName);

    if (!info.isEmpty())
        cetificateText.append("CN = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::EmailAddress);

    if (!info.isEmpty())
        cetificateText.append("emailAddress = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::DistinguishedNameQualifier);

    if (!info.isEmpty())
        cetificateText.append("dnQualifier = " + info.at(0) + ", ");

    info = subjectInfo(QSslCertificate::SerialNumber);

    if (!info.isEmpty())
        cetificateText.append("serialNumber = " + info.at(0) + ", ");

    cetificateText.chop(2);
    cetificateText.append("        Subject Public Key Info:\n            Public Key Algorithm: ");

    switch (d->publicKeyAlgorithm) {
    case QSsl::Opaque:
        cetificateText.append("opaqueEncryption\n");
        break;
    case QSsl::Rsa:
        cetificateText.append("rsaEncryption\n");
        break;
    case QSsl::Dsa:
        cetificateText.append("dsaEncryption\n");
        break;
    case QSsl::Ec:
        cetificateText.append("ecEncryption\n");
        break;
    }

    QSslKey key = publicKey();

    cetificateText.append("                Public-Key: (" + QByteArray::number(
                              key.length()) + " bit)\n");
    cetificateText.append("                Modulus:\n                    Unknown\n");
    cetificateText.append("                Exponent: Unknown\n");
    cetificateText.append("        X509v3 extensions:\n");
    cetificateText.append("    Signature Algorithm: Unknown\n");
    cetificateText.append("         Unknown\n");

    return cetificateText;
}

void QSslCertificatePrivate::init(const QByteArray &data, QSsl::EncodingFormat format)
{
    if (!data.isEmpty()) {
        const QList<QSslCertificate> certs = (format == QSsl::Pem)
            ? certificatesFromPem(data, 1)
            : certificatesFromDer(data, 1);
        if (!certs.isEmpty()) {
            *this = *certs.first().d;
        }
    }
}

static bool matchLineFeed(const QByteArray &pem, int *offset)
{
    char ch = 0;

    // ignore extra whitespace at the end of the line
    while (*offset < pem.size() && (ch = pem.at(*offset)) == ' ')
        ++*offset;

    if (ch == '\n') {
        *offset += 1;
        return true;
    }
    if (ch == '\r' && pem.size() > (*offset + 1) && pem.at(*offset + 1) == '\n') {
        *offset += 2;
        return true;
    }
    return false;
}

QList<QSslCertificate> QSslCertificatePrivate::certificatesFromPem(const QByteArray &pem, int count)
{
    QList<QSslCertificate> certificates;
    int offset = 0;
    while (count == -1 || certificates.size() < count) {
        int startPos = pem.indexOf(BEGINCERTSTRING, offset);
        if (startPos == -1)
            break;
        startPos += sizeof(BEGINCERTSTRING) - 1;
        if (!matchLineFeed(pem, &startPos))
            break;

        int endPos = pem.indexOf(ENDCERTSTRING, startPos);
        if (endPos == -1)
            break;

        offset = endPos + sizeof(ENDCERTSTRING) - 1;
        if (offset < pem.size() && !matchLineFeed(pem, &offset))
            break;

        QByteArray decoded = QByteArray::fromBase64(
            QByteArray::fromRawData(pem.data() + startPos, endPos - startPos));
        certificates << certificatesFromDer(decoded, 1);;
    }

    return certificates;
}

QList<QSslCertificate> QSslCertificatePrivate::certificatesFromDer(const QByteArray &der, int count)
{
    QList<QSslCertificate> certificates;

    QByteArray data = der;
    while (count == -1 || certificates.size() < count) {
        QSslCertificate cert;
        if (!cert.d->parse(data))
            break;

        certificates << cert;
        data.remove(0, cert.d->derData.size());
    }

    return certificates;
}

static QByteArray colonSeparatedHex(const QByteArray &value)
{
    QByteArray hexString;
    hexString.reserve(value.size() * 3);
    for (int a = 0; a < value.size(); ++a) {
        const quint8 b = value.at(a);
        if (b || !hexString.isEmpty()) { // skip leading zeros
            hexString += QByteArray::number(b, 16).rightJustified(2, '0');
            hexString += ':';
        }
    }
    hexString.chop(1);
    return hexString;
}

bool QSslCertificatePrivate::parse(const QByteArray &data)
{
    QAsn1Element root;

    QDataStream dataStream(data);
    if (!root.read(dataStream) || root.type() != QAsn1Element::SequenceType)
        return false;

    QDataStream rootStream(root.value());
    QAsn1Element cert;
    if (!cert.read(rootStream) || cert.type() != QAsn1Element::SequenceType)
        return false;

    // version or serial number
    QAsn1Element elem;
    QDataStream certStream(cert.value());
    if (!elem.read(certStream))
        return false;

    if (elem.type() == QAsn1Element::Context0Type) {
        QDataStream versionStream(elem.value());
        if (!elem.read(versionStream) || elem.type() != QAsn1Element::IntegerType)
            return false;

        versionString = QByteArray::number(elem.value().at(0) + 1);
        if (!elem.read(certStream))
            return false;
    } else {
        versionString = QByteArray::number(1);
    }

    // serial number
    if (elem.type() != QAsn1Element::IntegerType)
        return false;
    serialNumberString = colonSeparatedHex(elem.value());

    // algorithm ID
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    // issuer info
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    QByteArray issuerDer = data.mid(dataStream.device()->pos() - elem.value().length(), elem.value().length());
    issuerInfo = elem.toInfo();

    // validity period
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    QDataStream validityStream(elem.value());
    if (!elem.read(validityStream) || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType))
        return false;

    notValidBefore = elem.toDateTime();
    if (!elem.read(validityStream) || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType))
        return false;

    notValidAfter = elem.toDateTime();

    // subject name
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    QByteArray subjectDer = data.mid(dataStream.device()->pos() - elem.value().length(), elem.value().length());
    subjectInfo = elem.toInfo();
    subjectMatchesIssuer = issuerDer == subjectDer;

    // public key
    qint64 keyStart = certStream.device()->pos();
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    publicKeyDerData.resize(certStream.device()->pos() - keyStart);
    QDataStream keyStream(elem.value());
    if (!elem.read(keyStream) || elem.type() != QAsn1Element::SequenceType)
        return false;


    // key algorithm
    if (!elem.read(elem.value()) || elem.type() != QAsn1Element::ObjectIdentifierType)
        return false;

    const QByteArray oid = elem.toObjectId();
    if (oid == RSA_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Rsa;
    else if (oid == DSA_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Dsa;
    else if (oid == EC_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Ec;
    else
        publicKeyAlgorithm = QSsl::Opaque;

    certStream.device()->seek(keyStart);
    certStream.readRawData(publicKeyDerData.data(), publicKeyDerData.size());

    // extensions
    while (elem.read(certStream)) {
        if (elem.type() == QAsn1Element::Context3Type) {
            if (elem.read(elem.value()) && elem.type() == QAsn1Element::SequenceType) {
                QDataStream extStream(elem.value());
                while (elem.read(extStream) && elem.type() == QAsn1Element::SequenceType) {
                    QSslCertificateExtension extension;
                    if (!parseExtension(elem.value(), &extension))
                        return false;
                    extensions << extension;

                    if (extension.oid() == QLatin1String("2.5.29.17")) {
                        // subjectAltName
                        QAsn1Element sanElem;
                        if (sanElem.read(extension.value().toByteArray()) && sanElem.type() == QAsn1Element::SequenceType) {
                            QDataStream nameStream(sanElem.value());
                            QAsn1Element nameElem;
                            while (nameElem.read(nameStream)) {
                                if (nameElem.type() == QAsn1Element::Rfc822NameType) {
                                    subjectAlternativeNames.insert(QSsl::EmailEntry, nameElem.toString());
                                } else if (nameElem.type() == QAsn1Element::DnsNameType) {
                                    subjectAlternativeNames.insert(QSsl::DnsEntry, nameElem.toString());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    derData = data.left(dataStream.device()->pos());
    null = false;
    return true;
}

bool QSslCertificatePrivate::parseExtension(const QByteArray &data, QSslCertificateExtension *extension)
{
    bool ok;
    bool critical = false;
    QAsn1Element oidElem, valElem;

    QDataStream seqStream(data);

    // oid
    if (!oidElem.read(seqStream) || oidElem.type() != QAsn1Element::ObjectIdentifierType)
        return false;
    const QByteArray oid = oidElem.toObjectId();

    // critical and value
    if (!valElem.read(seqStream))
        return false;
    if (valElem.type() == QAsn1Element::BooleanType) {
        critical = valElem.toBool(&ok);
        if (!ok || !valElem.read(seqStream))
            return false;
    }
    if (valElem.type() != QAsn1Element::OctetStringType)
        return false;

    // interpret value
    QAsn1Element val;
    bool supported = true;
    QVariant value;
    if (oid == "1.3.6.1.5.5.7.1.1") {
        // authorityInfoAccess
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::SequenceType)
            return false;
        QVariantMap result;
        const auto elems = val.toVector();
        for (const QAsn1Element &el : elems) {
            QVector<QAsn1Element> items = el.toVector();
            if (items.size() != 2)
                return false;
            const QString key = QString::fromLatin1(items.at(0).toObjectName());
            switch (items.at(1).type()) {
            case QAsn1Element::Rfc822NameType:
            case QAsn1Element::DnsNameType:
            case QAsn1Element::UniformResourceIdentifierType:
                result[key] = items.at(1).toString();
                break;
            }
        }
        value = result;
    } else if (oid == "2.5.29.14") {
        // subjectKeyIdentifier
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::OctetStringType)
            return false;
        value = colonSeparatedHex(val.value()).toUpper();
    } else if (oid == "2.5.29.19") {
        // basicConstraints
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::SequenceType)
            return false;

        QVariantMap result;
        QVector<QAsn1Element> items = val.toVector();
        if (items.size() > 0) {
            result[QStringLiteral("ca")] = items.at(0).toBool(&ok);
            if (!ok)
                return false;
        } else {
            result[QStringLiteral("ca")] = false;
        }
        if (items.size() > 1) {
            result[QStringLiteral("pathLenConstraint")] = items.at(1).toInteger(&ok);
            if (!ok)
                return false;
        }
        value = result;
    } else if (oid == "2.5.29.35") {
        // authorityKeyIdentifier
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::SequenceType)
            return false;
        QVariantMap result;
        const auto elems = val.toVector();
        for (const QAsn1Element &el : elems) {
            if (el.type() == 0x80) {
                const QString key = QStringLiteral("keyid");
                result[key] = el.value().toHex();
            } else if (el.type() == 0x82) {
                const QString serial = QStringLiteral("serial");
                result[serial] = colonSeparatedHex(el.value());
            }
        }
        value = result;
    } else {
        supported = false;
        value = valElem.value();
    }

    extension->d->critical = critical;
    extension->d->supported = supported;
    extension->d->oid = QString::fromLatin1(oid);
    extension->d->name = QString::fromLatin1(oidElem.toObjectName());
    extension->d->value = value;

    return true;
}

QT_END_NAMESPACE

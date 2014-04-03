#include "qtreadabilityauth.h"
#include "qtreadabilityauth_p.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QStringList>
#include <QDebug>

QtReadabilityAuthPrivate::QtReadabilityAuthPrivate()
{
    qsrand(QTime::currentTime().msec());
    this->callbackUrl = QUrl("http://example.com"); // Default callback url
}


QtReadabilityAuthPrivate::~QtReadabilityAuthPrivate()
{
    qDebug() << Q_FUNC_INFO;
}



QtReadabilityAuth::QtReadabilityAuth(QObject *parent) :
    QObject(parent),
    d_ptr(new QtReadabilityAuthPrivate)
{
}

QtReadabilityAuth::~QtReadabilityAuth()
{
    delete d_ptr;
}

// Setters
void QtReadabilityAuth::setType(QtReadabilityAuth::RequestType type)
{
    d_ptr->requestType = type;
}

void QtReadabilityAuth::setConsumerKey(const QString &consumerKey)
{
    d_ptr->consumerKey = consumerKey;
}

void QtReadabilityAuth::setConsumerSecret(const QString &consumerSecret)
{
    d_ptr->consumerSecret = consumerSecret;
}

void QtReadabilityAuth::setCallbackUrl(const QUrl &callbackUrl)
{
    d_ptr->callbackUrl = callbackUrl;
}

void QtReadabilityAuth::setToken(const QString &token)
{
    d_ptr->oauthToken = token;
}

void QtReadabilityAuth::setTokenSecret(const QString &tokenSecret)
{
    d_ptr->oauthTokenSecret = tokenSecret;
}

void QtReadabilityAuth::setVerifier(const QString &verifier)
{
#ifdef QT5
    d_ptr->oauthVerifier = QUrl::fromPercentEncoding(verifier.toLatin1());
#else
    d_ptr->oauthVerifier = QUrl::fromPercentEncoding(verifier.toAscii());
#endif
}

// Getters
QtReadabilityAuth::RequestType QtReadabilityAuth::type() const
{
    return d_ptr->requestType;
}

QString QtReadabilityAuth::token() const
{
    return d_ptr->oauthToken;
}

QString QtReadabilityAuth::tokenSecret() const
{
    return d_ptr->oauthTokenSecret;
}

// Helper function to avoid writting "QString(QUrl::toPercentEncoding(xxx)" 10 times
inline QString encode(QString string) { return QString(QUrl::toPercentEncoding(string)); }

QByteArray QtReadabilityAuth::generateAuthHeader(const QUrl &requestUrl,
                                                 QtReadabilityAuth::HttpMethod httpMethod,
                                                 const QMultiMap<QString, QString> &params)
{
    QString timestamp;
    QString nonce;
#if QT_VERSION >= 0x040700
    timestamp = QString::number(QDateTime::currentDateTimeUtc().toTime_t());
#else
    timestamp = QString::number(QDateTime::currentDateTime().toUTC().toTime_t());
#endif
    nonce = QString::number(qrand());

    if (!requestUrl.isValid()) {
        qWarning() << "OAuth::Token: Invalid url. The request will probably be invalid";
    }

    // Step 1. Get all the oauth params for this request

    QMultiMap<QString, QString> oauthParams;

    oauthParams.insert("oauth_consumer_key", d_ptr->consumerKey);
    oauthParams.insert("oauth_signature_method", "HMAC-SHA1");
    oauthParams.insert("oauth_timestamp", timestamp);
    oauthParams.insert("oauth_nonce", nonce);
    oauthParams.insert("oauth_version", "1.0");

    switch (d_ptr->requestType) {
    case REQUEST_TOKEN:
        oauthParams.insert("oauth_callback", d_ptr->callbackUrl.toString());
        break;

    case ACCESS_TOKEN:
        oauthParams.insert("oauth_token", d_ptr->oauthToken);
        oauthParams.insert("oauth_verifier", d_ptr->oauthVerifier);
        break;
    case XAUTH_LOGIN:
        d_ptr->oauthTokenSecret = "";
        break;
    case AUTHORIZED:
        oauthParams.insert("oauth_token", d_ptr->oauthToken);
        break;
    }

    // Step 2. Take the parameters from the url, and add the oauth params to them
    QMultiMap<QString, QString> allParams = oauthParams;
#ifdef QT5
    QList<QPair<QString, QString> > queryItems = QUrlQuery(requestUrl.query()).queryItems();
#else
    QList<QPair<QString, QString> > queryItems = requestUrl.queryItems();
#endif
    for(int i = 0; i < queryItems.count(); ++i) {
        allParams.insert(queryItems[i].first, queryItems[i].second);
    }

    allParams.unite(params);

    // Step 3. Calculate the signature from those params, and append the signature to the oauth params

    QString signature = generateSignature(requestUrl, allParams, httpMethod);
    allParams.insert("oauth_signature", signature);

    // Step 4. Concatenate all oauth params into one comma-separated string

    QByteArray authHeader;

    authHeader = "OAuth ";

    QMultiMap<QString, QString>::const_iterator p = allParams.constBegin();
    while (p != allParams.constEnd()) {
        authHeader += QString("%1=\"%2\",").arg(p.key()).arg(encode(p.value()));
        ++p;
    }
    authHeader.chop(1); // remove the last character (the trailing ",")

    return authHeader;
}


/*!
  \internal
  Generates the OAuth signature.
  \see http://oauth.net/core/1.0a/#signing_process
*/
QString QtReadabilityAuth::generateSignature(const QUrl &requestUrl,
                                             const QMultiMap<QString, QString> &requestParameters,
                                             QtReadabilityAuth::HttpMethod method) const
{
    QString key = encode(d_ptr->consumerSecret) + "&" + encode(d_ptr->oauthTokenSecret);
    QString baseString;

    switch (method) {
    case GET:    baseString = "GET&";    break;
    case POST:   baseString = "POST&";   break;
    case PUT:    baseString = "PUT&";    break;
    case DELETE: baseString = "DELETE&"; break;
    case HEAD:   baseString = "HEAD&";   break;
    }

    baseString += encode(requestUrl.toString(QUrl::RemoveQuery)) + "&";

    // encode and concatenate the parameters into a string
    QStringList params;
    QMap<QString, QString>::const_iterator p = requestParameters.constBegin();
    while (p != requestParameters.constEnd()) {
        params << QString("%1=%2").arg(encode(p.key())).arg(encode(p.value()));
        ++p;
    }
    qSort(params);

    baseString += encode(params.join("&"));

    // Ok, we have the normalized base string and the key, calculate the HMAC-SHA1 signature
    return hmac_sha1(baseString, key);
}


/*!
  Calculates the HMAC-SHA1 signature from a message and a key.
  This method comes from the kQOAuth library (http://www.d-pointer.com/solutions/kqoauth/)
  Author: Johan Paul (johan.paul@d-pointer.com)
*/
QString QtReadabilityAuth::hmac_sha1(const QString& message, const QString& key) const
{
#ifdef QT5
    QByteArray keyBytes = key.toLatin1();
#else
    QByteArray keyBytes = key.toAscii();
#endif
    int keyLength;              // Length of key word
    const int blockSize = 64;   // Both MD5 and SHA-1 have a block size of 64.

    keyLength = keyBytes.size();
    // If key is longer than block size, we need to hash the key
    if (keyLength > blockSize) {
        QCryptographicHash hash(QCryptographicHash::Sha1);
        hash.addData(keyBytes);
        keyBytes = hash.result();
    }

    /* http://tools.ietf.org/html/rfc2104  - (1) */
    // Create the opad and ipad for the hash function.
    QByteArray ipad;
    QByteArray opad;

    ipad.fill( 0, blockSize);
    opad.fill( 0, blockSize);

    ipad.replace(0, keyBytes.length(), keyBytes);
    opad.replace(0, keyBytes.length(), keyBytes);

    /* http://tools.ietf.org/html/rfc2104 - (2) & (5) */
    for (int i=0; i<64; i++) {
        ipad[i] = ipad[i] ^ 0x36;
        opad[i] = opad[i] ^ 0x5c;
    }

    QByteArray workArray;
    workArray.clear();

    workArray.append(ipad, 64);
    /* http://tools.ietf.org/html/rfc2104 - (3) */
#ifdef QT5
    workArray.append(message.toLatin1());
#else
    workArray.append(message.toAscii());
#endif


    /* http://tools.ietf.org/html/rfc2104 - (4) */
    QByteArray sha1 = QCryptographicHash::hash(workArray, QCryptographicHash::Sha1);

    /* http://tools.ietf.org/html/rfc2104 - (6) */
    workArray.clear();
    workArray.append(opad, 64);
    workArray.append(sha1);

    sha1.clear();

    /* http://tools.ietf.org/html/rfc2104 - (7) */
    sha1 = QCryptographicHash::hash(workArray, QCryptographicHash::Sha1);
    return QString(sha1.toBase64());
}

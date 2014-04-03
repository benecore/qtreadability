#include "qtreadability.h"
#include "qtreadability_p.h"
#include "qtreadabilityauth.h"
#include <QtNetwork>
#include <QSslError>
#include <QDesktopServices>
#include <QMap>
#include <QUrl>
#include <QEventLoop>


const char* const REQUEST_TOKEN = "https://www.readability.com/api/rest/v1/oauth/request_token/";
const char* const AUTHORIZE = "https://www.readability.com/api/rest/v1/oauth/authorize/";
const char* const ACCESS_TOKEN = "https://www.readability.com/api/rest/v1/oauth/access_token/";
// XAUTH url
const char* const XAUTH_ENDPOINT = "https://www.readability.com/api/rest/v1/oauth/access_token/";
// API Endpoint
const char* const API_ENDPOINT = "https://www.readability.com/api/rest/v1/";


QtReadabilityPrivate::QtReadabilityPrivate(QtReadability *parent) :
    synchronous(true),
    auth(new QtReadabilityAuth),
    manager(new QNetworkAccessManager),
    loop(new QEventLoop),
    q_ptr(parent)
{
    Q_Q(QtReadability);
    manager->setParent(q);
    auth->setParent(q);
    loop->setParent(q);

    q->connect(manager, SIGNAL(finished(QNetworkReply*)),
            q,
            SLOT(replyReceived(QNetworkReply*)));
    q->connect(manager, SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),
            q,
            SLOT(sslErrors(QNetworkReply*,QList<QSslError>)));
    q->connect(manager, SIGNAL(finished(QNetworkReply*)),
               loop,
               SLOT(quit()));
}


QtReadabilityPrivate::~QtReadabilityPrivate()
{
}


void QtReadabilityPrivate::executeRequest(const QUrl &requestUrl, const QString &httpMethod, const QtReadabilityParams &requestParams)
{
    QNetworkRequest request(requestUrl);

    if (httpMethod == "GET"){
        request.setRawHeader("Authorization", auth->generateAuthHeader(request.url()));
        manager->get(request);
    }else if (httpMethod == "POST"){
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        if (!requestParams.isEmpty()){
            request.setRawHeader("Authorization", auth->generateAuthHeader(request.url(), QtReadabilityAuth::POST, requestParams));
            manager->post(request, paramsToByteArray(requestParams));
        }else{
            request.setRawHeader("Authorization", auth->generateAuthHeader(request.url(), QtReadabilityAuth::POST));
            manager->post(request, QByteArray());
        }
    }else if (httpMethod == "PUT"){
        manager->put(request, paramsToByteArray(requestParams));
    }else if (httpMethod == "DELETE"){
        request.setRawHeader("Authorization", auth->generateAuthHeader(request.url(), QtReadabilityAuth::DELETE));
        manager->deleteResource(request);
    }else if (httpMethod == "HEAD"){
        manager->head(request);
    }
    if (synchronous)
        loop->exec();
}


QByteArray QtReadabilityPrivate::paramsToByteArray(const QtReadabilityParams &params)
{
    QByteArray postParams;
    QtReadabilityParams::const_iterator i = params.constBegin();
    while(i != params.end()){
        postParams += i.key()+"="+i.value()+"&";
        ++i;
    }
    postParams.chop(1);
    return postParams;
}

void QtReadabilityPrivate::setApiRequest(QtReadability::ApiRequest request)
{
    this->apiRequest = request;
}

void QtReadabilityPrivate::clearTokens()
{
    auth->setToken("");
    auth->setTokenSecret("");
}


QtReadability::QtReadability(QObject *parent) :
    QObject(parent),
    d_ptr(new QtReadabilityPrivate(this))
{
}

QtReadability::QtReadability(const QString &consumerKey,
                             const QString &consumerSecret,
                             QObject *parent) :
    QObject(parent),
    d_ptr(new QtReadabilityPrivate(this))
{
    Q_D(QtReadability);

    d->consumerKey = consumerKey;
    d->consumerSecret = consumerSecret;
    d->auth->setConsumerKey(d->consumerKey);
    d->auth->setConsumerSecret(d->consumerSecret);
}


QtReadability::QtReadability(const QString &consumerKey,
                             const QString &consumerSecret,
                             const QUrl &callbackUrl,
                             QObject *parent) :
    QObject(parent),
    d_ptr(new QtReadabilityPrivate(this))
{
    Q_D(QtReadability);

    d->consumerKey = consumerKey;
    d->consumerSecret = consumerSecret;
    d->callbackUrl = callbackUrl;
    d->auth->setConsumerKey(d->consumerKey);
    d->auth->setConsumerSecret(d->consumerSecret);
    d->auth->setCallbackUrl(d->callbackUrl);
}


QtReadability::~QtReadability()
{
    delete d_ptr;
}

void QtReadability::getRequestToken()
{
    Q_D(QtReadability);
    if (d->consumerKey.isEmpty() || d->consumerSecret.isEmpty()){
        qWarning() << Q_FUNC_INFO << "consumerKey or consumerSecret is not set";
        return;
    }
    d->clearTokens(); // clear existing tokens;
    d->auth->setType(QtReadabilityAuth::REQUEST_TOKEN);
    d->auth->setConsumerKey(d->consumerKey);
    d->auth->setConsumerSecret(d->consumerSecret);
    d->auth->setCallbackUrl(d->callbackUrl);

    d->executeRequest(QUrl(REQUEST_TOKEN));
}


void QtReadability::getAuthorization(bool openBrowser)
{
    Q_D(QtReadability);
    d->auth->setToken(d->token);
    d->auth->setTokenSecret(d->tokenSecret);
#ifdef QT5
    QUrlQuery query;
    query.addQueryItem("oauth_token", d->token.toLatin1());
    QUrl url(AUTHORIZE);
    url.setQuery(query);
#else
    QUrl url(AUTHORIZE);
    url.addEncodedQueryItem("oauth_token", d->token.toAscii());
#endif
    if (openBrowser)
        QDesktopServices::openUrl(url);
    else
        emit authorizationUrlReceived(url);
}

void QtReadability::getAccessToken()
{
    Q_D(QtReadability);
    if (!d->callbackUrl.isEmpty()){
        d->auth->setCallbackUrl(d->callbackUrl);
    }else{
        qDebug() << "callback url not set | default is http://example.com";
    }
    if (d->verifier.isEmpty()){
        qWarning() << Q_FUNC_INFO << "verifier is not set";
        return;
    }
    if (d->token.isEmpty()){
        qWarning() << Q_FUNC_INFO << "oauth_token is not set";
        return;
    }
    if (d->tokenSecret.isEmpty()){
        qWarning() << Q_FUNC_INFO << "oauth_token_secret is not set";
        return;
    }
    d->auth->setVerifier(d->verifier);
    d->auth->setType(QtReadabilityAuth::ACCESS_TOKEN);

    d->executeRequest(QUrl(ACCESS_TOKEN), "POST");
}


void QtReadability::xAuthLogin(const QString &username, const QString &password)
{
    Q_D(QtReadability);
    d->auth->setType(QtReadabilityAuth::XAUTH_LOGIN);
    QUrl url(XAUTH_ENDPOINT);
#ifdef QT5
    QUrlQuery query;
    query.addQueryItem("x_auth_username", username.trimmed());
    query.addQueryItem("x_auth_password", password.trimmed());
    query.addQueryItem("x_auth_mode", "client_auth");
    url.setQuery(query);
#else
    url.addEncodedQueryItem("x_auth_username", username.trimmed().toUtf8().toPercentEncoding());
    url.addEncodedQueryItem("x_auth_password", password.trimmed().toUtf8().toPercentEncoding());
    url.addQueryItem("x_auth_mode", "client_auth");
#endif
    d->executeRequest(url, "POST");
}

void QtReadability::getArticle(const QString &articleId)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::GET_ARTICLE);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);
    QUrl url(QString("%1articles/%2").arg(API_ENDPOINT).arg(articleId));

    d->executeRequest(url);
}

void QtReadability::getBookmarks(const QtReadabilityParams &filters)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::GET_BOOKMARKS);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);
    QString query;
    QtReadabilityParams::const_iterator i = filters.constBegin();
    while (i != filters.constEnd()){
        if (!QString(i.value()).isEmpty())
            query += i.key() + "=" + i.value() + "&";
        ++i;
    }
    if (!query.isEmpty()){
        query.prepend("?");
        query.chop(1);
    }

    QUrl url(QString("%1bookmarks%2").arg(API_ENDPOINT).arg(query));

    d->executeRequest(url);
}


void QtReadability::addBookmark(const QString &anyUrl,
                                const int &favorite,
                                const int &archive,
                                const int allow_duplicates)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::ADD_BOOKMARK);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1bookmarks").arg(API_ENDPOINT));

    QtReadabilityParams params;
    params.insert("url", anyUrl.toUtf8().toPercentEncoding());
    params.insert("favorite", QString::number(favorite));
    params.insert("archive", QString::number(archive));
    params.insert("allow_duplicates", QString::number(allow_duplicates));

    d->executeRequest(url, "POST", params);
}

void QtReadability::getBookmark(const QString &bookmarkId)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::GET_BOOKMARK);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1bookmarks/%2").arg(API_ENDPOINT).arg(bookmarkId));

    d->executeRequest(url);
}

void QtReadability::updateBookmark(const QString &bookmarkId,
                                   const int &favorite,
                                   const int &archive,
                                   const float &read_percent)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::UPDATE_BOOKMARK);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1bookmarks/%2").arg(API_ENDPOINT).arg(bookmarkId));

    QtReadabilityParams params;
    params.insert("favorite", QString::number(favorite));
    params.insert("archive", QString::number(archive));
    params.insert("read_percent", QString::number(read_percent));

    d->executeRequest(url, "POST", params);
}


void QtReadability::deleteBookmark(const QString &bookmarkId)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::DELETE_BOOKMARK);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1bookmarks/%2").arg(API_ENDPOINT).arg(bookmarkId));

    d->executeRequest(url, "DELETE");
}


void QtReadability::getBookmarkTags(const QString &bookmarkId)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::GET_BOOKMARK_TAGS);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1bookmarks/%2/tags").arg(API_ENDPOINT).arg(bookmarkId));

    d->executeRequest(url);
}

void QtReadability::addTagsToBookmark(const QString &bookmarkId, const QString &tags)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::ADD_TAGS_TO_BOOKMARK);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1bookmarks/%2/tags").arg(API_ENDPOINT).arg(bookmarkId));

    QtReadabilityParams params;
    params.insert("tags", QUrl::toPercentEncoding(tags));

    d->executeRequest(url, "POST", params);
}


void QtReadability::deleteTagFromBookmark(const QString &bookmarkId, const QString &tagId)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::DELETE_TAG_FROM_BOOKMARK);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1bookmarks/%2/tags/%3").arg(API_ENDPOINT).arg(bookmarkId).arg(tagId));

    d->executeRequest(url, "DELETE");
}

void QtReadability::getTags()
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::GET_TAGS);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1tags").arg(API_ENDPOINT));

    d->executeRequest(url);
}

void QtReadability::getTag(const QString &tagId)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::GET_TAG);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1tags/%2").arg(API_ENDPOINT).arg(tagId));

    d->executeRequest(url);
}

void QtReadability::deleteTag(const QString &tagId)
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::DELETE_TAG);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1tags/%2").arg(API_ENDPOINT).arg(tagId));

    d->executeRequest(url, "DELETE");
}


void QtReadability::getUserInfo()
{
    Q_D(QtReadability);
    d->setApiRequest(QtReadability::GET_USER_INFO);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);

    QUrl url(QString("%1users/_current").arg(API_ENDPOINT));

    d->executeRequest(url);
}


void QtReadability::getShortUrl(const QString &sourceUrl)
{
    Q_D(QtReadability);
    d->auth->setType(QtReadabilityAuth::AUTHORIZED);
    d->setApiRequest(QtReadability::GET_SHORT_URL);
    QUrl url("http://www.readability.com/api/shortener/v1/urls");

    QtReadabilityParams params;
    params.insert("url", QUrl::toPercentEncoding(sourceUrl));

    d->executeRequest(url, "POST", params);
}


QtReadability::ApiRequest QtReadability::apiRequest() const
{
    Q_D(const QtReadability);
    return d->apiRequest;
}



QtReadability::OAuthError QtReadability::lastError() const
{
    Q_D(const QtReadability);
    return d->error;
}


qint32 QtReadability::errorCode() const
{
    Q_D(const QtReadability);
    return d->errorCode;
}


QtReadabilityHeaders QtReadability::replyHeaders() const
{
    Q_D(const QtReadability);
    return d->replyHeaders;
}

QNetworkAccessManager *QtReadability::networkManager() const
{
    Q_D(const QtReadability);
    return d->manager;
}


bool QtReadability::synchronous() const
{
    Q_D(const QtReadability);
    return d->synchronous;
}

void QtReadability::setNetworkManager(QNetworkAccessManager *manager)
{
    Q_D(QtReadability);
    d->manager = manager;
}


void QtReadability::setSynchronous(const bool &synchronousRequests)
{
    Q_D(QtReadability);
    if (d->synchronous != synchronousRequests)
        d->synchronous = synchronousRequests;
}


QString QtReadability::errorString() const
{
    Q_D(const QtReadability);
    return d->errorString;
}

void QtReadability::setConsumerKey(const QString &consumerKey)
{
    Q_D(QtReadability);
    d->consumerKey = consumerKey;
    d->auth->setConsumerKey(d->consumerKey);
}

void QtReadability::setConsumerSecret(const QString &consumerSecret)
{
    Q_D(QtReadability);
    d->consumerSecret = consumerSecret;
    d->auth->setConsumerSecret(d->consumerSecret);
}

void QtReadability::setVerifier(const QString &verifier)
{
    Q_D(QtReadability);
    d->verifier = verifier;
}

void QtReadability::setCallbackUrl(const QUrl &callbackUrl)
{
    Q_D(QtReadability);
    d->callbackUrl = callbackUrl;
    d->auth->setCallbackUrl(d->callbackUrl);
}

void QtReadability::setToken(const QString &token)
{
    Q_D(QtReadability);
    d->token = token;
    d->auth->setToken(d->token);
}

void QtReadability::setTokenSecret(const QString &tokenSecret)
{
    Q_D(QtReadability);
    d->tokenSecret = tokenSecret;
    d->auth->setTokenSecret(d->tokenSecret);
}


void QtReadability::replyReceived(QNetworkReply *reply)
{
    Q_D(QtReadability);
    switch (reply->error()) {
    case QNetworkReply::NoError:
        d->error = QtReadability::NoError;
        break;

    case QNetworkReply::ContentAccessDenied:
    case QNetworkReply::ContentOperationNotPermittedError:
    case QNetworkReply::AuthenticationRequiredError:
    case QNetworkReply::ProtocolFailure:
        d->error = QtReadability::RequestUnauthorized;
        break;

    default:
        d->error = QtReadability::NetworkError;
        break;
    }

    d->errorCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    d->errorString = reply->errorString();

    QByteArray replyString = reply->readAll();

    if (d->auth->type() == QtReadabilityAuth::REQUEST_TOKEN
            || d->auth->type() == QtReadabilityAuth::ACCESS_TOKEN
            || d->auth->type() == QtReadabilityAuth::XAUTH_LOGIN){
        QMap<QString, QString> response;
        QStringList parameters = QString(replyString).split('&', QString::SkipEmptyParts);
        foreach (const QString &pair, parameters) {
            QStringList p = pair.split('=');
            if (p.count() == 2){
#ifdef QT5
                response.insert(p[0], QUrl::fromPercentEncoding(p[1].toLatin1()));
#else
                response.insert(p[0], QUrl::fromPercentEncoding(p[1].toAscii()));
#endif
            }
        }

        if (d->error == QtReadability::NoError
                && (response["oauth_token"].isEmpty() || response["oauth_token_secret"].isEmpty())) {
            d->error = QtReadability::RequestUnauthorized;
        }

        d->token = response["oauth_token"];
        d->tokenSecret = response["oauth_token_secret"];
        d->auth->setToken(d->token);
        d->auth->setTokenSecret(d->tokenSecret);

        switch (d->auth->type()){
        case QtReadabilityAuth::REQUEST_TOKEN:
            if (d->error == QtReadability::NoError)
                d->auth->setType(QtReadabilityAuth::ACCESS_TOKEN);
            emit requestTokenReceived(response);
            break;
        case QtReadabilityAuth::ACCESS_TOKEN:
            if (d->error == QtReadability::NoError)
                d->auth->setType(QtReadabilityAuth::AUTHORIZED);
            emit accessTokenReceived(response);
            break;
        case QtReadabilityAuth::XAUTH_LOGIN:
            if (d->error == QtReadability::NoError)
                d->auth->setType(QtReadabilityAuth::AUTHORIZED);
            emit accessTokenReceived(response);
            break;
        default:
            break;
        }
    }else{

        // Reply headers
        QList<QByteArray> headers = reply->rawHeaderList();
        foreach(const QByteArray &header, headers){
            d->replyHeaders.insert(header, reply->rawHeader(header));
        }

        emit responseReceived(replyString);

    }

    reply->deleteLater();
}


void QtReadability::sslErrors(QNetworkReply *reply, const QList<QSslError> & errors)
{
    reply->ignoreSslErrors(errors);
}

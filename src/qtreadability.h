/*
*	QtReadability - A Readability.com library for Qt
*
*	Copyright (c) 2014 Zoltán Benke (benecore@devpda.net)
*                      	 http://devpda.net
*
*	The MIT License (MIT)
*
*	Permission is hereby granted, free of charge, to any person obtaining a copy of
*	this software and associated documentation files (the "Software"), to deal in
*	the Software without restriction, including without limitation the rights to
*	use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
*	the Software, and to permit persons to whom the Software is furnished to do so,
*	subject to the following conditions:
*
*	The above copyright notice and this permission notice shall be included in all
*	copies or substantial portions of the Software.
*
*	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
*	FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
*	COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
*	IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
*	CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef QTREADABILITY_H
#define QTREADABILITY_H

#include "qtreadability_export.h"
#include <QObject>
#include <QUrl>
#include <QMultiMap>
#include <QMap>

class QNetworkReply;
class QNetworkAccessManager;
class QSslError;

typedef QMultiMap<QString, QString> QtReadabilityParams;
typedef QMap<QString, QString> QtReadabilityHeaders;

class QtReadabilityPrivate;
class QTREADABILITYSHARED_EXPORT QtReadability : public QObject
{
    Q_OBJECT
public:
    explicit QtReadability(QObject *parent = 0);
    explicit QtReadability(const QString &consumerKey, const QString &consumerSecret, QObject *parent = 0);
    explicit QtReadability(const QString &consumerKey, const QString &consumerSecret, const QUrl &callbackUrl, QObject *parent = 0);
    virtual ~QtReadability();


    enum OAuthError{
        NoError = 0,
        NetworkError = 1,
        RequestUnauthorized = 2
    };


    enum ApiRequest{
        GET_ARTICLE,
        GET_BOOKMARKS,
        ADD_BOOKMARK,
        GET_BOOKMARK,
        UPDATE_BOOKMARK,
        DELETE_BOOKMARK,
        GET_BOOKMARK_TAGS,
        ADD_TAGS_TO_BOOKMARK,
        DELETE_TAG_FROM_BOOKMARK,
        GET_TAGS,
        GET_TAG,
        DELETE_TAG,
        GET_USER_INFO,
        GET_SHORT_URL
    };


    Q_INVOKABLE
    void getRequestToken();
    Q_INVOKABLE
    void getAuthorization(bool openBrowser = false);
    Q_INVOKABLE
    void getAccessToken();
    Q_INVOKABLE
    void xAuthLogin(const QString &username, const QString &password);
    Q_INVOKABLE
    void getArticle(const QString &articleId);
    Q_INVOKABLE
    void getBookmarks(const QtReadabilityParams &filters = QtReadabilityParams());
    Q_INVOKABLE
    void addBookmark(const QString &anyUrl, const int &favorite = 0, const int &archive = 0, const int allow_duplicates = 0);
    Q_INVOKABLE
    void getBookmark(const QString &bookmarkId);
    Q_INVOKABLE
    void updateBookmark(const QString &bookmarkId, const int &favorite, const int &archive, const float &read_percent = 0.0);
    Q_INVOKABLE
    void deleteBookmark(const QString &bookmarkId);
    Q_INVOKABLE
    void getBookmarkTags(const QString &bookmarkId);
    Q_INVOKABLE
    void addTagsToBookmark(const QString &bookmarkId, const QString &tags);
    Q_INVOKABLE
    void deleteTagFromBookmark(const QString &bookmarkId, const QString &tagId);
    Q_INVOKABLE
    void getTags();
    Q_INVOKABLE
    void getTag(const QString &tagId);
    Q_INVOKABLE
    void deleteTag(const QString &tagId);
    Q_INVOKABLE
    void getUserInfo();
    Q_INVOKABLE
    void getShortUrl(const QString &sourceUrl);

    ApiRequest apiRequest() const;
    // Last error
    OAuthError lastError() const;
    // Error string
    QString errorString() const;
    // Http erro code
    qint32 errorCode() const;
    // Reply headers
    QtReadabilityHeaders replyHeaders() const;
    // Get networkManager instance
    QNetworkAccessManager *networkManager() const;
    // is requests synchronous
    bool synchronous() const;


signals:
    void requestTokenReceived(QMap<QString, QString> response);
    void authorizationUrlReceived(QUrl authorizationUrl);
    void accessTokenReceived(QMap<QString, QString> response);
    void responseReceived(QByteArray response);


public slots:
    // Setters
    void setNetworkManager(QNetworkAccessManager *manager);
    void setSynchronous(const bool &synchronousRequests);
    void setConsumerKey(const QString &consumerKey);
    void setConsumerSecret(const QString &consumerSecret);
    void setVerifier(const QString &verifier);
    void setCallbackUrl(const QUrl &callbackUrl);
    void setToken(const QString &token);
    void setTokenSecret(const QString &tokenSecret);



private slots:
    void replyReceived(QNetworkReply *reply);
    void sslErrors(QNetworkReply *reply, const QList<QSslError> & errors);


private:
    QtReadabilityPrivate *const d_ptr;
    Q_DECLARE_PRIVATE(QtReadability)
    Q_DISABLE_COPY(QtReadability)
};

#endif // QTREADABILITY_H

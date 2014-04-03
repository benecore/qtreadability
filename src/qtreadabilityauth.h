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

#ifndef QTREADABILITYAUTH_H
#define QTREADABILITYAUTH_H

#include "qtreadability_export.h"
#include <QObject>
#include <QUrl>
#ifdef QT5
#include <QUrlQuery>
#endif
#include <QMultiMap>

class QtReadabilityAuthPrivate;
class QTREADABILITYSHARED_EXPORT QtReadabilityAuth : public QObject
{
    Q_OBJECT
public:
    explicit QtReadabilityAuth(QObject *parent = 0);
    virtual ~QtReadabilityAuth();


    enum RequestType{
        REQUEST_TOKEN,
        ACCESS_TOKEN,
        XAUTH_LOGIN,
        AUTHORIZED
    };

    enum HttpMethod{
        GET,
        POST,
        PUT,
        DELETE,
        HEAD
    };


public slots:
    // Setters
    void setType(RequestType type);
    void setConsumerKey(const QString& consumerKey);
    void setConsumerSecret(const QString& consumerSecret);
    void setCallbackUrl(const QUrl& callbackUrl);
    void setToken(const QString& token);
    void setTokenSecret(const QString& tokenSecret);
    void setVerifier(const QString& verifier);

    // Getters
    QtReadabilityAuth::RequestType type() const;
    QString token() const;
    QString tokenSecret() const;



    QByteArray generateAuthHeader(const QUrl &requestUrl,
                                  HttpMethod httpMethod = GET,
                                  const QMultiMap<QString, QString> &params = QMultiMap<QString, QString>());

private slots:
    QString generateSignature(const QUrl& requestUrl, const QMultiMap<QString, QString>& requestParameters, HttpMethod method) const;
    QString hmac_sha1(const QString& message, const QString& key) const;

private:
    QtReadabilityAuthPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(QtReadabilityAuth)
    Q_DISABLE_COPY(QtReadabilityAuth)
};

#endif // QTREADABILITYAUTH_H

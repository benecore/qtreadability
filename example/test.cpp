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

#include "test.h"
#include <iostream>
#include <QDebug>

using namespace std;

Test::Test(QObject *parent) :
    QObject(parent)
{
    read = new QtReadability("CLIENT_ID", "CLIENT_SECRET", this);

    connect(read, SIGNAL(requestTokenReceived(QMap<QString,QString>)),
            this,
            SLOT(requestTokenReceived(QMap<QString,QString>)));
    connect(read, SIGNAL(authorizationUrlReceived(QUrl)),
            this,
            SLOT(authorizationUrlReceived(QUrl)));
    connect(read, SIGNAL(accessTokenReceived(QMap<QString,QString>)),
            this,
            SLOT(accessTokenReceived(QMap<QString,QString>)));
    connect(read, SIGNAL(responseReceived(QByteArray)),
            this,
            SLOT(responseReceived(QByteArray)));

    read->getRequestToken(); // Get request token
}


void Test::requestTokenReceived(QMap<QString, QString> response)
{
    qDebug() << endl << "REQUEST TOKEN RECEIVED";
    QMap<QString, QString>::const_iterator i = response.constBegin();
    while (i != response.constEnd()){
        qDebug() << "KEY:" << i.key() << "VALUE:" << i.value();
        ++i;
    }
    read->getAuthorization(true); // authorize

    string verifier;
    cout << endl << "Enter verifier: ";
    getline(cin, verifier);
    if (verifier == ""){
        qDebug() << "verifier is empty";
        return;
    }
    read->setVerifier(QString::fromStdString(verifier));

    read->getAccessToken(); // get access token
}

void Test::authorizationUrlReceived(QUrl authorizationUrl)
{
    qDebug() << endl << "Authorization url received" << authorizationUrl.toString();
}

void Test::accessTokenReceived(QMap<QString, QString> response)
{
    qDebug() << endl << "ACCESS TOKENS RECEIVED";
    QMap<QString, QString>::const_iterator i = response.constBegin();
    while (i != response.constEnd()){
        qDebug() << "KEY:" << i.key() << "VALUE:" << i.value();
        ++i;
    }

    read->setToken(response.value("oauth_token"));
    read->setTokenSecret(response.value("oauth_token_secret"));

    // save tokens for later usage

    QtReadabilityParams filters;
    filters.insert("page", "1");
    filters.insert("per_page", "5");

    read->getBookmarks(filters);
}

void Test::responseReceived(QByteArray response)
{
    qDebug() << endl << "RESPONSE RECEIVED" << endl;
    if (read->lastError() == QtReadability::NoError){
        qDebug() << "HEADERS:";
        QtReadabilityHeaders::const_iterator i = read->replyHeaders().constBegin();
        while(i != read->replyHeaders().constEnd()){
            qDebug() << i.key() << "|" << i.value();
            ++i;
        }
        switch (read->apiRequest()) {
        case QtReadability::GET_BOOKMARKS:
            qDebug() << endl << "BOOKMARKS:" << endl << response;
            break;
        case QtReadability::GET_USER_INFO:
            qDebug() << endl << "USER INFO:" << endl << response;
            break;
        default:
            break;
        }
    }else{
        qDebug() << "ERROR CODE:" << read->errorCode() << endl << \
                    "ERROR STRING:" << read->errorString();
    }
}

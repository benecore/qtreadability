# QtReadability #

A Readability.com library for Qt. It supports 

----------
## License: ##
[READ](LICENSE.md)

## Basic usage ##

Create a QtReadability instance
    
    readability = new QtReadability("CONSUMER_KEY", "CONSUMER_SECRET", this)
*connect to the signals*
    
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

----------

### Get access tokens ###
**Web:**

**1.** Get request token

    readability->getRequestToken();
requestTokenReceived(QMap<QString,QString>) signal is emitted when is finished.

**2.** Authorize

    ...requestTokenReceived(QMap<QString, QString> response){

		QMap<QString, QString>::const_iterator i = response.constBegin();
    	while (i != response.constEnd()){
        	qDebug() << "KEY:" << i.key() << "VALUE:" << i.value();
        	++i;
    	}
		// true = open browser
		// false = emit authorizationUrlReceived(QUrl authorizationUrl) signal
		readability->getAuthorization(true)
		// SET VERIFIER
		readability->setVerifier("OAUTH_VERIFIER");
		// GET ACCESS TOKEN
		readability->getAccessToken();
    }
accessTokenReceived(QMap<QString,QString>) is emitted when is finished.

**3.** Access token

    ...accessTokenReceived(QMap<QString,QString> response)){
    
    		readability->setToken(response.value("oauth_token"));
    		readability->setTokenSecret(response.value("oauth_token_secret"));
    		
    		// Save tokens for later usage
    }


**XAuth:**

    readability->xAuthLogin("USERANME", "PASSWORD");
accessTokenReceived(QMap<QString,QString>) is emitted when is finished.

----------

### Further usage ###
Use the access tokens for any further usage.

**responseReceived(QByteArray response)** signal is emitted for all request except (getRequestToken, getAuthorization, getAccessToken)

**getBookmarks(const QtReadabilityParams &filters)** you can filter output according this query params
[https://www.readability.com/developers/api/reader#idp38160](https://www.readability.com/developers/api/reader#idp38160)

	readability->setToken("OAUTH_TOKEN");
	readability->setTokenSecret("OAUTH_TOKEN_SECRET");
	
	// Filter output according this parameters 
    QtReadabilityParams filters;
	filters.insert("page", "1");
    filters.insert("per_page", "5");

	readability->getBookmarks(filters);
parse output

    ...responseReceived(QByteArray response){
    	qDebug() << endl << "RESPONSE RECEIVED" << endl;
    	if (read->lastError() == QtReadability::NoError){ // No error
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

----------

### Credits: ###
QtReadabilityAuth class is based on SimpleOAuth by Gregory Schlomoff `(gregory.schlomoff@gmail.com)`
[https://github.com/gregschlom/SimpleOAuth](https://github.com/gregschlom/SimpleOAuth "SimpleOAuth")

### Contact: ###
	In case of any questions, feel free to contact me:
    Zoltán Benke benecore@devpda.net
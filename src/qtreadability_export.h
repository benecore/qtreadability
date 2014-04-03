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

#ifndef QTREADABILITY_EXPORT_H
#define QTREADABILITY_EXPORT_H

#include <QtCore/qglobal.h>

#if defined(QTREADABILITY)
#  define QTREADABILITYSHARED_EXPORT Q_DECL_EXPORT
#else
#  define QTREADABILITYSHARED_EXPORT Q_DECL_IMPORT
#endif

#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
#define QT5
#endif

const qint32 QTREADABILITY_BAD_REQUEST = 400;
const qint32 QTREADABILITY_AUTH_REQUIRED = 401;
const qint32 QTREADABILITY_FORBIDDEN = 403;
const qint32 QTREADABILITY_NOT_FOUND = 404;
const qint32 QTREADABILITY_INTERNAL_SERVER_ERROR = 500;
/* Create an article */
const qint32 QTREADABILITY_ARTICLE_CREATED = 201;
const qint32 QTREADABILITY_ARTICLE_RECREATED = 202;
const qint32 QTREADABILITY_ARTICLE_EXISTS = 409;
/* Delete an article */
const qint32 QTREADABILITY_ARTICLE_DELETED = 204; // Or tag deleted


#endif // QTREADABILITY_EXPORT_H

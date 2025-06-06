// pull in Q_OS_ defines
#include <QtGlobal>

// Windows
#if defined(Q_OS_WIN)
#   include <windows.h>
#endif

// openssl
#include <openssl/crypto.h>

// Qt
#if defined(Q_OS_WIN)
#   include <QAbstractNativeEventFilter>
#endif
#include <QApplication>
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QHostAddress>
#include <QIcon>
#include <QJsonArray>
#include <QJsonObject>
#include <QLibraryInfo>
#include <QLockFile>
#include <QMessageBox>
#include <QObject>
#include <QSettings>
#include <QStandardPaths>
#include <QTranslator>
#include <QRandomGenerator>

// tego
#include <tego/tego.hpp>

#ifdef TEGO_VERSION
#   define TEGO_STR2(X) #X
#   define TEGO_STR(X) TEGO_STR2(X)
#   define TEGO_VERSION_STR TEGO_STR(TEGO_VERSION)
#else
#   define TEGO_VERSION_STR "devbuild"
#endif

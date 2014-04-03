#include <QCoreApplication>

#include "test.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    Test *test = new Test;

    int result = a.exec();

    delete test;

    return result;
}

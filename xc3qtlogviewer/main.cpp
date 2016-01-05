#include "stdafx.h"

#include <qapplication.h>

#include "CMainWindow.hpp"

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);

	QCoreApplication::setOrganizationName("mhRr");
	QCoreApplication::setApplicationName("xc3logviewer");

	CMainWindow mainWindow;
	mainWindow.show();
	return app.exec();
}

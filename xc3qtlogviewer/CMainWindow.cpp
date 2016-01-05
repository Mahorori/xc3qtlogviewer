#include "stdafx.h"

#include <time.h>

#include "CMainWindow.hpp"
#include "rijndael.h"
#include "xc3.h"

CMainWindow::CMainWindow() : QMainWindow()
{
	setObjectName("MainWindow");
	setWindowTitle(tr("XC3 LOG VIEWER"));

	QSettings settings("mhRr", "xc3logviewer");

	// window ƒTƒCƒY
	// setMaximumSize(1024, 768);
	setMinimumSize(512, 384);
	resize(settings.value("x").toInt(), settings.value("y").toInt());

	pTextEdit = new QTextEdit();
	pTextEdit->setReadOnly(true);

	setCentralWidget(pTextEdit);

	createActions();
	createMenus();
	createToolBars();
	createStatusBar();
}

CMainWindow::~CMainWindow()
{
	QSettings settings("mhRr", "xc3logviewer");
	
	settings.setValue("x", size().width());
	settings.setValue("y", size().height());
}

void CMainWindow::closeEvent(QCloseEvent *event)
{
	QMessageBox msgBox;
	msgBox.setText(tr("Why you leaving bitch"));
	msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
	msgBox.setDefaultButton(QMessageBox::Cancel);

	if (msgBox.exec() == QMessageBox::Cancel)
	{
		event->ignore();
	}
	else
	{
		event->accept();
	}
}

void CMainWindow::createActions()
{
	pActionOpen = new QAction(tr("&Open(&O)"), this);

	// this is shown at status bar when user mouse over
	pActionOpen->setStatusTip(tr("Open encrypted log file."));
	connect(pActionOpen, SIGNAL(triggered()), this, SLOT(open()));

	pActionAbout = new QAction(tr("&About(&A)"), this);
	// this is shown at status bar when user mouse over
	pActionAbout->setStatusTip(tr("Show information about this application."));
	connect(pActionAbout, SIGNAL(triggered()), this, SLOT(about()));
}

void CMainWindow::createMenus()
{
	// create menus
	this->pFileMenu = menuBar()->addMenu(tr("&File(&F)"));
	// sub menus
	this->pFileMenu->addAction(pActionOpen);
	this->pFileMenu->addSeparator();
	this->pFileMenu->addAction(tr("&Exit(&X)"), this, SLOT(close()));

	this->pEditMenu = menuBar()->addMenu(tr("&Edit(&E)"));
	// sub menus
	// this->pEditMenu->addAction();

	this->pHelpMenu = menuBar()->addMenu(tr("&Help(&H)"));
	// sub menus
	this->pHelpMenu->addAction(pActionAbout);
}

void CMainWindow::createToolBars()
{
}

void CMainWindow::createStatusBar()
{
	// create status bar and set msg
	pStatusBar = new QStatusBar();

	pProgressBar = new QProgressBar();

	pProgressBar->setMinimum(0);
	pProgressBar->setMaximum(3000);
	pProgressBar->setTextVisible(false);
	pProgressBar->show();

	pLabel = new QLabel(tr("ready"));
	pLabel->setMinimumWidth(100);

	pStatusBar->addWidget(pLabel);
	pStatusBar->addWidget(pProgressBar, 1);

	setStatusBar(pStatusBar);
}

bool CMainWindow::decrypt(HANDLE hFile)
{
	XC3_LOG_BUFFER	buffer;
	XC3_LOG_TAILS	tails;
	XC3_LOG_CTX		ctx;

	DWORD		dwNumberOfBytesRead;
	char		sign_dst[5];
	struct tm	tm;
	char		buf_temp[80];
	int			index_end = -1;

	SetFilePointer(hFile, -int(sizeof XC3_LOG_TAILS), 0, FILE_END);

	if (!ReadFile(hFile, &tails, sizeof(XC3_LOG_TAILS), &dwNumberOfBytesRead, NULL))
	{
		statusBar()->showMessage(tr("couldn't read log file GLE : %1").arg(GetLastError()));
		return false;
	}
	if (dwNumberOfBytesRead < sizeof(XC3_LOG_TAILS))
	{
		statusBar()->showMessage(tr("EOF"));
		return true;
	}

	if (tails.signature != XC3_LOG_SIGNATURE1)
	{
		// copy signature
		memcpy(sign_dst, &tails.signature, 4);
		sign_dst[4] = 0;

		statusBar()->showMessage(tr("signature doesn't match : %1 %2").arg(sign_dst, tails.signature));
		return false;
	}
	if (tails.index < 3000)
	{
		// beginning of the file
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	}
	else if (tails.index == 3000)
	{
		if (tails.position != 0)
		{
			SetFilePointer(hFile, tails.position - 4, 0, FILE_BEGIN);

			if (!ReadFile(hFile, &index_end, 4, &dwNumberOfBytesRead, NULL))
			{
				// _tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
				return false;
			}
		}

		SetFilePointer(hFile, tails.position, 0, FILE_BEGIN);
	}
	else
	{
		// _tprintf(TEXT("log file is broken. index : %d\n"), tails.index);
		return false;
	}

	//
	this->pProgressBar->setMaximum(tails.index);
	//

	do
	{
		// load buffer
		if (!ReadFile(hFile, &buffer, sizeof(XC3_LOG_BUFFER), &dwNumberOfBytesRead, NULL))
		{
			// _tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
			return false;
		}
		if (dwNumberOfBytesRead == 0)
		{
			if (tails.position == 0)
			{
				// success
				return true;
			}
			else
			{
				// beginning of the file
				SetFilePointer(hFile, 0, 0, FILE_BEGIN);
				continue;
			}
		}
		if (buffer.signature != XC3_LOG_SIGNATURE2)
		{
			// copy signature
			memcpy(sign_dst, &buffer.signature, 4);
			sign_dst[4] = 0;

			printf("signature doesn't match : %s 0x%08X\n", sign_dst, buffer.signature);
			return false;
		}
		if (buffer.size > sizeof(XC3_LOG_BUFFER))
		{
			// _tprintf(TEXT("log file is broken  buffer.size : %d\n"), buffer.size);
			return false;
		}

		switch (buffer.type)
		{
			case 9039:
			{
				// B8 4F 23 00 00 C7 06 6D 4C 78 7A
				// fuck this shit just ignore plez
				// sprintf_s(buffer.buffer, "client closed(?) with error code : 0x%08X", buffer.errorcode);
				// printf(buffer.buffer);
				// printf("\n");

				// update progress bar
				this->pProgressBar->setValue(pProgressBar->value() + 1);

				// load tails
				if (!ReadFile(hFile, &tails, sizeof(XC3_LOG_TAILS), &dwNumberOfBytesRead, NULL))
				{
					// _tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
					return false;
				}
				if (tails.index != index_end)
					continue;
				else
					return true;

				break;
			}
			case 9040:
			{
				// ZeroMemory(&ctx, sizeof(ctx));
				ctx.init(XC3_LOG_S1, strlen(XC3_LOG_S1));

				for (int i = 0; i < sizeof(buffer.buffer); i++)
					buffer.buffer[i] ^= ctx.calc();

				break;
			}
			case 9041:
			{
				//
				int keysize = 16;
				rijndael_key rijndael;
				unsigned char *buf_temp = (unsigned char*)buffer.buffer;

				if (rijndael_keysize(&keysize))
					return false;

				if (rijndael_setup(buffer.key, keysize, 0, &rijndael))
					return false;

				int a = sizeof(buffer.buffer) / 16;

				if (a > 0)
				{
					for (int i = 0; i < a; i++)
					{
						if (rijndael_ecb_decrypt(buf_temp, buf_temp, &rijndael))
							return false;

						buf_temp += keysize;
					}
				}

				break;
			}
			default:
			{
				// copy type
				memcpy(sign_dst, &buffer.type, 2);
				sign_dst[2] = 0;

				// _tprintf(TEXT("unknown type : %s %04X\n"), sign_dst, buffer.type);
				break;
			}
		}

		_localtime32_s(&tm, &buffer.unix_time);
		strftime(buf_temp, sizeof(buf_temp), "[%Y-%m-%d %H:%M:%S] ", &tm);;

		pTextEdit->insertPlainText(buf_temp);

		if (buffer.name[0] != '\0')
		{
			pTextEdit->insertPlainText("[");
			pTextEdit->insertPlainText(buffer.name);
			pTextEdit->insertPlainText("]");
		}
		pTextEdit->insertPlainText(buffer.buffer);
		pTextEdit->insertPlainText("\r\n");

		//
		this->pProgressBar->setValue(pProgressBar->value() + 1);
		//

		// load tails
		if (!ReadFile(hFile, &tails, sizeof(XC3_LOG_TAILS), &dwNumberOfBytesRead, NULL))
		{
			// _tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
			return false;
		}
	} while (tails.index != index_end);

	return true;
}

void CMainWindow::open()
{

	QSettings settings("mhRr", "xc3logviewer");
	QString path = settings.value("url").toString();
	QString fn = QFileDialog::getOpenFileName(this, QString(), path, tr("Log Files (*.log)"));

	if (!fn.isEmpty())
	{
		settings.setValue("url", fn);

		HANDLE hFile = CreateFileW(fn.toStdWString().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile != INVALID_HANDLE_VALUE)
		{
			// reset progressbar
			pProgressBar->setValue(0);

			// clear text edit before decrypt
			pTextEdit->clear();

			decrypt(hFile);

			CloseHandle(hFile);
		}
	}
}

void CMainWindow::about()
{
	QMessageBox msgBox;
	QSpacerItem* horizontalSpacer = new QSpacerItem(200, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);
	msgBox.setText("mhRr is OP shit.");
	msgBox.setStandardButtons(QMessageBox::Ok);
	msgBox.setDefaultButton(QMessageBox::Ok);
	QGridLayout* layout = (QGridLayout*)msgBox.layout();
	layout->addItem(horizontalSpacer, layout->rowCount(), 0, 1, layout->columnCount());
	msgBox.exec();
}
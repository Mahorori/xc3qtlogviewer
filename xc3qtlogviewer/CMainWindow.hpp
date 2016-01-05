#pragma once

#include <qmainwindow.h>

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;
class QWidget;
class QTextEdit;
class QProgressBar;
class QStatusBar;
class QLabel;
QT_END_NAMESPACE

class CMainWindow : public QMainWindow
{
	Q_OBJECT

public:
	CMainWindow();
	~CMainWindow();

protected:
	void closeEvent(QCloseEvent *event) Q_DECL_OVERRIDE;

private:
	void createActions();
	void createMenus();
	void createToolBars();
	void createStatusBar();
	
private:
	bool decrypt(HANDLE hFile);

private slots:
	void open();
	void about();

private:
	QMenu *pFileMenu;
	QMenu *pEditMenu;
	QMenu *pHelpMenu;

	QAction *pActionOpen;
	QAction *pActionAbout;

	QTextEdit *pTextEdit;
	
	// status bar
	QStatusBar		*pStatusBar;
	QProgressBar	*pProgressBar;
	QLabel			*pLabel;
};
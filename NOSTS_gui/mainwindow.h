#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtCrypto>
#include <iostream>
#include <../NOSTS/nostsclientserver.h>

#define EXIT_STRING "#EXIT#"
#define STATUS_CONNECTION_NONE 0
#define STATUS_CONNECTION_DATA_READY 1

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    int getStatus();
    void resetInterface();
    void chatInterfaceOn();
    void enableConnectionInterface();
    void enableMessageExchange();
    void disableConnectionInterface();
    void disableMessageExchange();
    std::string getServerIP();
    std::string getServerPort();
    std::string getCaCertFilename();
    std::string getMyCertFilename();
    std::string getMyPrivateKeyFilename();
    std::string getPrivateKeyPasswd();
    bool getIsServer();
    void emitNewMessageSg(std::string message);
    int sendMessage(std::string message);
    void setClientServer(NOSTSClientServer *clientServer);
    // attributi
    int connectionDataStatus;
signals:
    void newMessageSg(QString message);
private slots:
    void handleSendButton();
    void handleRadioButton();
    void handleStartButton();
    void handleNewMessage(QString message);
private:
    void addMessage(std::string message);
    void addText(const QString &text);
    void closeEvent(QCloseEvent *event);
    // attributi
    Ui::MainWindow *ui;
    NOSTSClientServer *clientServer;
};

#endif // MAINWINDOW_H

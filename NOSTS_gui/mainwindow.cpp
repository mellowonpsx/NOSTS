#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>

#define DEFAULT_SERVER_CACERT "/home/mellowonpsx/.NOSTS/cert/rootca.crt"
#define DEFAULT_SERVER_MYCERT "/home/mellowonpsx/.NOSTS/cert/bob.crt"
#define DEFAULT_SERVER_MYPRIVATEKEY "/home/mellowonpsx/.NOSTS/cert/bob.key"
#define DEFAULT_SERVER_MYPRIVATEKEY_PASSWORD "password bob.key"
#define DEFAULT_CLIENT_CACERT "/home/mellowonpsx/.NOSTS/cert/rootca.crt"
#define DEFAULT_CLIENT_MYCERT "/home/mellowonpsx/.NOSTS/cert/alice.crt"
#define DEFAULT_CLIENT_MYPRIVATEKEY "/home/mellowonpsx/.NOSTS/cert/alice.key"
#define DEFAULT_CLIENT_MYPRIVATEKEY_PASSWORD "password alice.key"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->startButton, SIGNAL(clicked()), this, SLOT(handleStartButton()));
    connect(ui->serverRadioButton, SIGNAL(clicked()), this, SLOT(handleRadioButton()));
    connect(ui->clientRadioButton, SIGNAL(clicked()), this, SLOT(handleRadioButton()));
    connect(ui->messageSendButton, SIGNAL(clicked()), this, SLOT(handleSendButton()));
    connect(ui->messageInput, SIGNAL(returnPressed()), this, SLOT(handleSendButton()));
    connect(this, SIGNAL(newMessageSg(QString)), this, SLOT(handleNewMessage(QString)));
    ui->serverRadioButton->click();
    this->connectionDataStatus = STATUS_CONNECTION_NONE;
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    QMessageBox::StandardButton resBtn = QMessageBox::question( this, "NOSTS_gui",
                                                                tr("Are you sure?\n"),
                                                                QMessageBox::No | QMessageBox::Yes,
                                                                QMessageBox::Yes);
    if (resBtn != QMessageBox::Yes) {
        event->ignore();
    }else
    {
        this->sendMessage(EXIT_STRING);
        event->accept();
    }
}

void MainWindow::addText(const QString &text)
{
    QString plainText = ui->textOutput->toPlainText();
    plainText.append(text);
    ui->textOutput->setPlainText(plainText);
    //autoscroll
    QTextCursor c =  ui->textOutput->textCursor();
    c.movePosition(QTextCursor::End);
    ui->textOutput->setTextCursor(c);
}

void MainWindow::handleSendButton()
{
    if(ui->messageInput->text()!="")
    {
        std::string messaggio = ui->messageInput->text().toStdString();
        this->sendMessage(messaggio.c_str());
        messaggio = "#SENDING: "+messaggio+"\n";
        this->addText(messaggio.c_str());
        ui->messageInput->setText("");
    }
}

void MainWindow::handleNewMessage(QString message)
{
    this->addText(message);
}

int MainWindow::getStatus()
{
    return this->connectionDataStatus;
}

int MainWindow::sendMessage(std::string message)
{
    if(this->clientServer == NULL) return 1;
    if(this->clientServer->getStatus() == STATUS_KEY_EXCHANGED)
    {
        this->clientServer->sendEncryptedBlockingMessage(message);
        return 0;
    }
    return 1;
}

void MainWindow::setClientServer(NOSTSClientServer *clientServer)
{
    this->clientServer = clientServer;
}

void MainWindow::emitNewMessageSg(std::string message)
{
    emit newMessageSg(message.c_str());
}

void MainWindow::handleRadioButton()
{
    if(ui->clientRadioButton->isChecked())
    {
        ui->startButton->setText("Connect");
        ui->caCertInput->setText(DEFAULT_CLIENT_CACERT);
        ui->myCertInput->setText(DEFAULT_CLIENT_MYCERT);
        ui->myPrivateKeyInput->setText(DEFAULT_CLIENT_MYPRIVATEKEY);
        ui->myPrivateKeyPasswordInput->setText(DEFAULT_CLIENT_MYPRIVATEKEY_PASSWORD);
    }
    else //defautl option is server
    {
        ui->startButton->setText("Start Server");
        ui->caCertInput->setText(DEFAULT_SERVER_CACERT);
        ui->myCertInput->setText(DEFAULT_SERVER_MYCERT);
        ui->myPrivateKeyInput->setText(DEFAULT_SERVER_MYPRIVATEKEY);
        ui->myPrivateKeyPasswordInput->setText(DEFAULT_SERVER_MYPRIVATEKEY_PASSWORD);
    }
}

void MainWindow::enableConnectionInterface()
{
    ui->startButton->setEnabled(true);
    ui->serverIpInput->setEnabled(true);
    ui->serverPortInput->setEnabled(true);
    ui->serverRadioButton->setEnabled(true);
    ui->clientRadioButton->setEnabled(true);
    ui->caCertInput->setEnabled(true);
    ui->myCertInput->setEnabled(true);
    ui->myPrivateKeyInput->setEnabled(true);
    ui->myPrivateKeyPasswordInput->setEnabled(true);
}

void MainWindow::disableConnectionInterface()
{
    ui->startButton->setEnabled(false);
    ui->serverIpInput->setEnabled(false);
    ui->serverPortInput->setEnabled(false);
    ui->serverRadioButton->setEnabled(false);
    ui->clientRadioButton->setEnabled(false);
    ui->caCertInput->setEnabled(false);
    ui->myCertInput->setEnabled(false);
    ui->myPrivateKeyInput->setEnabled(false);
    ui->myPrivateKeyPasswordInput->setEnabled(false);
}

void MainWindow::enableMessageExchange()
{
    ui->messageInput->setEnabled(true);
    ui->messageSendButton->setEnabled(true);
    ui->textOutput->setEnabled(true);
}

void MainWindow::disableMessageExchange()
{
    ui->messageInput->setEnabled(false);
    ui->messageSendButton->setEnabled(false);
    ui->textOutput->setEnabled(false);
}

void MainWindow::handleStartButton()
{
    this->disableConnectionInterface();
    this->connectionDataStatus = STATUS_CONNECTION_DATA_READY;
}

void MainWindow::resetInterface()
{
    this->disableMessageExchange();
    this->enableConnectionInterface();
    this->connectionDataStatus = STATUS_CONNECTION_NONE;
}

void MainWindow::chatInterfaceOn()
{
    this->enableMessageExchange();
}

std::string MainWindow::getServerIP()
{
     return ui->serverIpInput->text().toStdString();
}

std::string MainWindow::getServerPort()
{
     return ui->serverPortInput->text().toStdString();
}

std::string MainWindow::getCaCertFilename()
{
     return ui->caCertInput->text().toStdString();
}

std::string MainWindow::getMyCertFilename()
{
     return ui->myCertInput->text().toStdString();
}

std::string MainWindow::getMyPrivateKeyFilename()
{
     return ui->myPrivateKeyInput->text().toStdString();
}

std::string MainWindow::getPrivateKeyPasswd()
{
     return ui->myPrivateKeyPasswordInput->text().toStdString();
}

bool MainWindow::getIsServer()
{
     if(ui->clientRadioButton->isChecked()) return false;
     return true;
}

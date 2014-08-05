#include "mainwindow.h"
#include <QApplication>

#include "../NOSTS/nostsclientserver.h"

NOSTSClientServer *clientServer;

int stringToInt(string numberString)
{
    stringstream messageText;
    messageText << numberString;
    int number;
    messageText >> number;
    return number;
}

string stringToInt(int number)
{
    stringstream messageText;
    messageText << number;
    string numberString;
    messageText >> numberString;
    return numberString;
}

void windowMain(MainWindow *w)
{
    bool ok = false;
    while(!ok)
    {
        while(w->getStatus() != STATUS_CONNECTION_DATA_READY)
        {
            //busy waiting
        }
        w->emitNewMessageSg("->Waiting for new connection\n");
        //connessione
        string serverIP = w->getServerIP();
        string serverPort = w->getServerPort();
        string caCertFilename = w->getCaCertFilename();
        string myCertFilename = w->getMyCertFilename();
        string myPrivateKeyFilename = w->getMyPrivateKeyFilename();
        string privateKeyPasswd = w->getPrivateKeyPasswd();

        if(!w->getIsServer())
        {
            clientServer = new NOSTSClientServer(CLIENT_MODE,serverIP, stringToInt(serverPort), true);
        }
        else clientServer = new NOSTSClientServer(SERVER_MODE,serverIP, stringToInt(serverPort), true);

        w->setClientServer(clientServer);

        if(clientServer->getStatus() == STATUS_ERROR)
        {
            w->resetInterface();
            w->emitNewMessageSg("Error: Error on Client/Server start\n");
            continue;
        }

        string message = "Status: "+stringToInt(clientServer->getStatus())+" - "+clientServer->getTextStatus()+"\n";
        w->emitNewMessageSg(message.c_str());

        if(clientServer->loadCACertificateFromFile(caCertFilename))
        {
            w->resetInterface();
            w->emitNewMessageSg("Error: Error on load caCert from "+caCertFilename+"\n");
            continue;
        }

        if(clientServer->loadMyCertificateFromFile(myCertFilename))
        {
            w->resetInterface();
            w->emitNewMessageSg("Error: Error on load myCert\n");
            continue;
        }

        if(clientServer->loadPrivateKey(myPrivateKeyFilename, privateKeyPasswd.c_str()))
        {
            w->resetInterface();
            w->emitNewMessageSg("Error: Error on load myPrivateKey\n");
            continue;
        }

        if(clientServer->getStatus() == STATUS_ERROR)
        {
            w->resetInterface();
            w->emitNewMessageSg("Error: Generic Error\n");
            continue;
        }

        w->emitNewMessageSg("->All certificate loaded, waiting for Key Exchange (may take time)\n");

        clientServer->setUpSTS();

        // check if auth is mutual
        if(clientServer->getStatus() != STATUS_KEY_EXCHANGED)
        {
            w->resetInterface();
            w->emitNewMessageSg("Error: Key Not Exchanged\n");
            continue;
        }

        w->chatInterfaceOn();
        w->emitNewMessageSg("->Mutual Auth Completed\n");
        ok = true;
    }

    bool running = true;
    while(clientServer->getStatus() == STATUS_KEY_EXCHANGED && running)
    {
        string clearMessage;
        clientServer->receiveEncryptedBlockingMessage(&clearMessage);
        if(clearMessage == EXIT_STRING)
        {
            running = false;
        }
        string message = "#RECEIVED from "+clientServer->getItsCertificateName()+": "+clearMessage+"\n";
        w->emitNewMessageSg(message.c_str());
    }
    if(running)
    {
        w->emitNewMessageSg("Error: status changed\n");
    }
    else
    {
        w->disableConnectionInterface();
        w->disableMessageExchange();
        w->emitNewMessageSg("Connection Closed\n");
    }
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    QtConcurrent::run(&windowMain, &w);
    a.exec();
    cout << "Program Ended" << endl;
    exit(0);
}

/*
    if(clientServer->loadCACertificateFromFile(caCertFilename))
    {
        this->enableConnectionInterface();
        //notify error!!
        return;
    }

    if(clientServer->loadMyCertificateFromFile(myCertFilename))
    {
        this->enableConnectionInterface();
        //notify error!!
        return;
    }

    if(clientServer->loadPrivateKey(myPrivateKeyFilename, privateKeyPasswd.c_str()))
    {
        this->enableConnectionInterface();
        //notify error!!
        return;
    }

    if(clientServer->getStatus() == STATUS_ERROR)
    {
        //cout << clientServer->getTextStatus() << endl;
        this->enableConnectionInterface();
        //notify error!!
        return;

    }

    clientServer->setUpSTS();

    // check if auth is mutual
    if(clientServer->getStatus() != STATUS_KEY_EXCHANGED)
    {
        this->enableConnectionInterface();
        //notify error!!
        return;
    }

    this->addText("Mutual Auth Completa\n");
    QFuture<void> future = QtConcurrent::run(this, &MainWindow::chatMessageIncome);
    this->enableMessageExchange();


void MainWindow::chatMessageIncome()
{
    while(this->clientServer->getStatus() == STATUS_KEY_EXCHANGED)
    {
        string clearMessage;
        this->clientServer->receiveEncryptedBlockingMessage(&clearMessage);
        string message = "#RECEIVED from "+this->clientServer->getItsCertificateName()+": "+clearMessage+"\n";
        emit newMessageSg(message.c_str());
        if(clearMessage == EXIT_STRING)
        {
            exit(0);
        }
    }
    cerr << "Error: status changed" << endl;
    exit(1);
}

void* MainWindow::chatMessageIncome(void * this_psd)
{
    MainWindow *this_passed = (MainWindow*)this_psd;
    while(this_passed->clientServer->getStatus() == STATUS_KEY_EXCHANGED)
    {
        string clearMessage;
        this_passed->clientServer->receiveEncryptedBlockingMessage(&clearMessage);
        if(clearMessage == EXIT_STRING)
        {
            //this->addText("#RECEIVED EXIT COMMAND\n");
            cout << "#RECEIVED EXIT COMMAND" << endl;
            exit(0);
        }
        string message = "#RECEIVED from "+this_passed->clientServer->getItsCertificateName()+": "+clearMessage+"\n";
        this_passed->addText(message.c_str());
        //cout << message;
    }
    cerr << "Error: status changed" << endl;
    exit(1);
}

*/

    //return a.exec();

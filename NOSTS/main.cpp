/*
 * NOSTS: NotOnlySTS is a TCP/IP secured message exchanger
 * based on STS-like implementation
 * made for Network Security class
*/

#include "nostsclientserver.h"
#include <QtCrypto>
#define EXIT_STRING "#EXIT#"

using namespace std;

void printHelp();
void printFeature();
int insertIntNumber(int min, int max, string testo);
int menu1();
char* getCmdOption(char ** begin, char ** end, const string& option);
bool cmdOptionExists(char** begin, char** end, const string& option);
int stringToInt(string numberString);
int main_app(int argc, char *argv[]);
//multithread
void* chatMessageIncome(void *threaddata);
int chatMessageSender(NOSTSClientServer *nostsClientServer);

int main(int argc, char *argv[])
{    
    // development main, argument decided
    int choosen = insertIntNumber(1, 4, "Choose:\n1-Server\n2-Client\n3-Help & QCA festures\n4-Exit");

    if(choosen == 4)
    {
        return 0;
    }

    if(choosen == 3)
    {
        char  def_arg0[] = "nosts";
        char  def_arg1[] = "--help";
        char  def_arg2[] = "--feature";
        char* def_argv[] = { &def_arg0[0], &def_arg1[0], &def_arg2[0],  NULL };
        int   def_argc   = (int)(sizeof(def_argv) / sizeof(def_argv[0])) - 1;
        return main_app(def_argc,def_argv);
    }

    // /home/mellowonpsx/Documents/Network\ Security/build-NOSTS-Desktop_Qt4-Debug/nosts --CAcert /home/mellowonpsx/Desktop/cert/rootca.crt --Clientcert /home/mellowonpsx/Desktop/cert/bob.crt --serverIP 127.0.0.1 --port 50000 --privateKey /home/mellowonpsx/Desktop/cert/bob.key --server --verbose
    // /home/mellowonpsx/Documents/Network\ Security/build-NOSTS-Desktop_Qt4-Debug/nosts --CAcert /home/mellowonpsx/Desktop/cert/rootca.crt --Clientcert /home/mellowonpsx/Desktop/cert/alice.crt --serverIP 127.0.0.1 --port 50000 --privateKey /home/mellowonpsx/Desktop/cert/alice.key --verbose

    if(choosen == 1)
    {
        char  def_arg0[] = "nosts";
        char  def_arg1[] = "--CAcert";
        char  def_arg2[] = "/home/mellowonpsx/Desktop/cert/rootca.crt";
        char  def_arg3[] = "--Clientcert";
        char  def_arg4[] = "/home/mellowonpsx/Desktop/cert/bob.crt";
        char  def_arg5[] = "--serverIP";
        char  def_arg6[] = "127.0.0.1";
        char  def_arg7[] = "--port";
        char  def_arg8[] = "50000";
        char  def_arg9[] = "--privateKey";
        char  def_arg10[] = "/home/mellowonpsx/Desktop/cert/bob.key";
        char  def_arg11[] = "--server"; // alternative form -s
        char  def_arg12[] = "--verbose"; // alternative form -s
        char* def_argv[] = { &def_arg0[0], &def_arg1[0], &def_arg2[0], &def_arg3[0], &def_arg4[0], &def_arg5[0], &def_arg6[0], &def_arg7[0], &def_arg8[0], &def_arg9[0], &def_arg10[0], &def_arg11[0], &def_arg12[0], NULL };
        int   def_argc   = (int)(sizeof(def_argv) / sizeof(def_argv[0])) - 1;
        return main_app(def_argc,def_argv);
    }
    char  def_arg0[] = "nosts";
    char  def_arg1[] = "--CAcert";
    char  def_arg2[] = "/home/mellowonpsx/Desktop/cert/rootca.crt";
    char  def_arg3[] = "--Clientcert";
    char  def_arg4[] = "/home/mellowonpsx/Desktop/cert/alice.crt";
    char  def_arg5[] = "--serverIP";
    char  def_arg6[] = "127.0.0.1";
    char  def_arg7[] = "--port";
    char  def_arg8[] = "50000";
    char  def_arg9[] = "--privateKey";
    char  def_arg10[] = "/home/mellowonpsx/Desktop/cert/alice.key";
    char  def_arg11[] = "-v"; // alternative form -s
    char* def_argv[] = { &def_arg0[0], &def_arg1[0], &def_arg2[0], &def_arg3[0], &def_arg4[0], &def_arg5[0], &def_arg6[0], &def_arg7[0], &def_arg8[0], &def_arg9[0], &def_arg10[0], &def_arg11[0], NULL };
    int   def_argc   = (int)(sizeof(def_argv) / sizeof(def_argv[0])) - 1;
    return main_app(def_argc,def_argv);

    // char  def_arg1[] = "--help"; //alternative form -h
    // normal main, only pass the arguments */
    return main_app(argc, argv);
}

int main_app(int argc, char *argv[])
{
    // option parsing
    // if help&feature|help|feature print and exit
    if((cmdOptionExists(argv, argv+argc, "-h")||cmdOptionExists(argv, argv+argc, "--help"))&&(cmdOptionExists(argv, argv+argc, "-f")||cmdOptionExists(argv, argv+argc, "--feature")))
    {
        //print help and feature
        printHelp();
        printFeature();
        return 0;
    }

    if(cmdOptionExists(argv, argv+argc, "-h")||cmdOptionExists(argv, argv+argc, "--help"))
    {
        //print help
        printHelp();
        return 0;
    }

    if(cmdOptionExists(argv, argv+argc, "-f")||cmdOptionExists(argv, argv+argc, "--feature"))
    {
        //print feature
        printFeature();
        return 0;
    }

    // check CAcert
    if(!cmdOptionExists(argv, argv+argc, "--CAcert"))
    {
        //errore
        cout << "--CAcert mandatory" << endl;
        return 1;
    }
    char *CAcert_filename = getCmdOption(argv, argv + argc, "--CAcert");
    if (!CAcert_filename)
    {
        //errore
        cout << "--CAcert content is missing" << endl;
        return 1;
    }

    // check Clientcert
    if(!cmdOptionExists(argv, argv+argc, "--Clientcert"))
    {
        //errore
        cout << "--Clientcert mandatory" << endl;
        return 1;
    }
    char *Clientcert_filename = getCmdOption(argv, argv + argc, "--Clientcert");
    if (!Clientcert_filename)
    {
        //errore
        cout << "--Clientcert content is missing" << endl;
        return 1;
    }

    // check serverIP
    if(!cmdOptionExists(argv, argv+argc, "--serverIP"))
    {
        //errore
        cout << "--serverIP mandatory" << endl;
        return 1;
    }
    char *serverIP = getCmdOption(argv, argv + argc, "--serverIP");
    if (!Clientcert_filename)
    {
        //errore
        cout << "--serverIP content is missing" << endl;
        return 1;
    }

    // check port
    if(!cmdOptionExists(argv, argv+argc, "--port"))
    {
        //errore
        cout << "--port mandatory" << endl;
        return 1;
    }
    char *serverPort = getCmdOption(argv, argv + argc, "--port");
    if (!Clientcert_filename)
    {
        //errore
        cout << "--port content is missing" << endl;
        return 1;
    }

    // check privateKey
    if(!cmdOptionExists(argv, argv+argc, "--privateKey"))
    {
        //errore
        cout << "--privateKey mandatory" << endl;
        return 1;
    }
    char *privateKey = getCmdOption(argv, argv + argc, "--privateKey");
    if (!privateKey)
    {
        //errore
        cout << "--privateKey content is missing" << endl;
        return 1;
    }

    /*// check privateKeyPasswd
    if(!cmdOptionExists(argv, argv+argc, "--privateKeyPasswd"))
    {
        //errore
        cout << "--privateKeyPasswd mandatory" << endl;
        return 1;
    }
    char *privateKeyPasswd = getCmdOption(argv, argv + argc, "--privateKeyPasswd");
    if (!privateKeyPasswd)
    {
        //errore
        cout << "--privateKeyPasswd content is missing" << endl;
        return 1;
    }*/

    bool verbose = false;
    if(cmdOptionExists(argv, argv+argc, "--verbose")||cmdOptionExists(argv, argv+argc, "-v"))
    {
        verbose = true;
    }

    // all option checked

    //if server start server, else start client
    NOSTSClientServer *clientServer;
    if(cmdOptionExists(argv, argv+argc, "--server")||cmdOptionExists(argv, argv+argc, "-s"))
    {
        // start server, open socket
        clientServer = new NOSTSClientServer(SERVER_MODE,serverIP, stringToInt(serverPort), verbose);
    }
    else clientServer  = new NOSTSClientServer(CLIENT_MODE,serverIP, stringToInt(serverPort), verbose);

    if(clientServer->getStatus() == STATUS_ERROR)
    {
        return 1;
    }
    // server and socket info
    cout << "status: " << clientServer->getStatus() << " - " << clientServer->getTextStatus() << endl;

    if(clientServer->loadCACertificateFromFile(CAcert_filename))
    {
        cout << "error load ca certificate" << endl;
        return 1;
    }

    if(clientServer->loadMyCertificateFromFile(Clientcert_filename))
    {
        cout << "error load client certificate" << endl;
        return 1;
    }

    string privateKeyPasswd;
    cout << "Insert privateKey(" << privateKey << ") password" << endl;
    getline(cin,privateKeyPasswd);
    if(clientServer->loadPrivateKey(privateKey, privateKeyPasswd.c_str()))
    {
        cout << "error load private key" << endl;
        return 1;
    }

    if(clientServer->getStatus() == STATUS_ERROR)
    {
        cout << clientServer->getTextStatus() << endl;
        return 1;
    }

    //cout << "status: " << clientServer->getStatus() << " - " << clientServer->getTextStatus() << endl;

    clientServer->setUpSTS();

    // check if auth is mutual
    if(!verbose)
    {
        if(!(clientServer->getStatus() == STATUS_KEY_EXCHANGED))
        {
            cout << "Error on key exchange" << endl;
            return 1;
        }else
        {
            cout << "Mutual auth completed" << endl;
            return 1;
        }
    }

    //multithread message exchange
    //start multithread for message income
    pthread_t thread;
    int rc = pthread_create( &thread, NULL, chatMessageIncome, (void *) clientServer);
    if (rc)
    {
        cerr << "Error on thread" << endl;
        exit(1);
    }
    //non-multithread for message send
    return chatMessageSender(clientServer);
}

int chatMessageSender(NOSTSClientServer *nostsClientServer)
{
    while(nostsClientServer->getStatus() == STATUS_KEY_EXCHANGED)
    {
        string clearMessage;
        getline(cin,clearMessage);
        if(clearMessage == EXIT_STRING)
        {
            cout << "#SENDING EXIT COMMAND" << endl;
            nostsClientServer->sendEncryptedBlockingMessage(clearMessage);
            return 0;
        }
        nostsClientServer->sendEncryptedBlockingMessage(clearMessage);
    }
    return 0;
}

void* chatMessageIncome(void *threaddata)
{
    NOSTSClientServer *nostsClientServer;
    nostsClientServer = (NOSTSClientServer * ) threaddata;
    while(nostsClientServer->getStatus() == STATUS_KEY_EXCHANGED)
    {
        string clearMessage;
        nostsClientServer->receiveEncryptedBlockingMessage(&clearMessage);
        if(clearMessage == EXIT_STRING)
        {
            //if(cin) cout << endl;
            if(cin.gcount()) cout << endl;
            cout << "#RECEIVED EXIT COMMAND" << endl;
            exit(0);
        }
        if(cin.gcount())
        {
            cout << endl;
            cout << "#RECEIVED from " << nostsClientServer->getItsCertificateName() << ": " << clearMessage << endl;
        } else cout << "#RECEIVED from " << nostsClientServer->getItsCertificateName() << ": " << clearMessage << endl;
    }
    //if exiting it probably be an error
    cerr << "Error: status changed" << endl;
    exit(1);
}

int insertIntNumber(int min, int max, string testo)
{
    int input;
    bool valid = false;
    while(!valid)
    {
        cout << testo << endl;
        cin >> input;
        if(cin.fail())
        {
            cout << "must be a number" << endl << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(),'\n');
        }
        else
        {
            if(input>=min&&input<=max)
                valid = true;
            else
                cout << "number must belong to I = [" << min << "," << max << "]" << endl << endl;
        }
    }
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(),'\n');
    return input;
}

int stringToInt(string numberString)
{
    stringstream messageText;
    messageText << numberString;
    int number;
    messageText >> number;
    return number;
}

char* getCmdOption(char ** begin, char ** end, const string& option)
{
    char ** itr = find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const string& option)
{
    return find(begin, end, option) != end;
}

void printHelp()
{
    cout << "** NOSTS Not Only STS v 0.1 **"<< endl;
    cout << "Network Security Class of 2014, Sergio Leoni - 59775" << endl;
    cout << "ATTENTION: Pay attention to start server before start client"<< endl;
    cout << "DISCLAIMER: Educational use only "<< endl;
    //cout << "** NOSTS Not Only STS v 0.1 **"<< endl;
}

void printFeature()
{
    cout << "Aviable QCA feature" << endl;
    QCA::init();
    cout << "Feature aviable: ";
    foreach(QString str,QCA::supportedFeatures())
    {
        cout << str.toStdString() << ", ";
    }
    cout << "END" << endl;
}

// codice utile ma non usato
/*

string parameters = Mpz_tToStr(g)+DELIMITER+Mpz_tToStr(p)+DELIMITER+Mpz_tToStr(A);
string parameters = receiveMessageWithSocket(socket);
string g_c = parameters.substr(0,parameters.find(DELIMITER));
parameters = parameters.substr(parameters.find(DELIMITER)+DELIMITER_LENGTH,parameters.length()-parameters.find(DELIMITER));
string p_c = parameters.substr(0,parameters.find(DELIMITER));
parameters = parameters.substr(parameters.find(DELIMITER)+DELIMITER_LENGTH,parameters.length()-parameters.find(DELIMITER));
string A_c = parameters.substr(0,parameters.find(DELIMITER));
*/
//cout << "Signature2: " << decoder64.arrayToString(securedArray2.toByteArray().toBase64()).toStdString() << endl << endl;
// verificate sign
/*string g_b_a = Mpz_tToStr(B)+Mpz_tToStr(A);
QByteArray signature = Clientkey.signMessage(QCA::MemoryRegion(g_b_a.c_str()), Clientcert.signatureAlgorithm());*/
/*
QCA::SecureArray ephimeralKey = Mpz_tToStr(K_text).c_str();
QCA::SymmetricKey K(ephimeralKey);
QCA::InitializationVector iv(256);

QCA::Cipher cipherDecode(QString("aes256"),
                   QCA::Cipher::CBC,
                   QCA::Cipher::DefaultPadding,
                   QCA::Decode,
                   K,
                   iv);
//
QCA::SecureArray securedArray = cipher.update(signature);
*/

/*//B, CERT_b, Encrypt_k(Sign_b(g^b,g^a));
string g_b_a = Mpz_tToStr(B)+Mpz_tToStr(A);

QByteArray signature = Clientkey.signMessage(QCA::MemoryRegion(g_b_a.c_str()), Clientcert.signatureAlgorithm());

QCA::SecureArray ephimeralKey = Mpz_tToStr(K_text).c_str();
QCA::SymmetricKey K(ephimeralKey);
QCA::InitializationVector iv(256);

QCA::Cipher cipher(QString("aes256"),
                   QCA::Cipher::CBC,
                   QCA::Cipher::DefaultPadding,
                   QCA::Encode,
                   K,
                   iv);
QCA::SecureArray securedArray = cipher.update(signature);


//QCA::BigInteger B = QCA::BigInteger(QString::fromStdString(receiveMessageWithSocket(socket)));
// calculate K = B^a mod p
//QCA::BigInteger K = B;
//K^= a;
//K%= p;
//cout << "The Ephimeral Key for this session is: " << K.toString() << endl;*/
/*while(1)
{
    //
    sendMessageWithSocket(socket, "ti mando questo messaggio: ciao");
    string message = receiveMessageWithSocket(socket);
    cout << "server: " << message << endl;
}
cout << endl;*/

/*QCA::Certificate CAcert(CAcert_filename);
if(CAcert.isNull())
{
    cout << "Sorry, could not import CA cert " << endl;
    return 1;
}
else
{
    if(!CAcert.isCA())
    {
        cout << "Sorry, the CA certificate is not a valid CA" << endl;
        return 1;
    }
}



    //check if is server


return 0;

QCA::Certificate Clientcert(Clientcert_filename);
if (Clientcert.isNull())
{
    cout << "Sorry, could not import Client certificate" << endl;
    return 1;
}
else
{
    if(!CAcert.isIssuerOf(Clientcert))
    {
        cout << "CA certificate is not an issuer of Client certificate" << endl;
        return 1;
    }
}*/

//QCA::CertificateCollection systemcerts = QCA::systemStore();
//certlist = systemcerts.certificates();

//std::cout << "Number of certificates: " << certlist.count() << std::endl;
/*if (argc >= 2) {
    // we are going to read the certificates in using a single call
    // which requires a CertificateCollection.
    QCA::CertificateCollection filecerts;
    // The conversion can be tested (although you don't have to) to find out if it
    // worked.
    QCA::ConvertResult importResult;
    // This imports all the PEM encoded certificates from the file specified as the argument
    // Note that you pass in a pointer to the result argument.
    filecerts = QCA::CertificateCollection::fromFlatTextFile( argv[1], &importResult );
    if ( QCA::ConvertGood == importResult) {
        std::cout << "Import succeeded" << std::endl;
        // this turns the CertificateCollection into a QList of Certificate objects
        certlist = filecerts.certificates();
    }
} else {
    // we have no arguments, so just use the system certificates
    if ( !QCA::haveSystemStore() ) {
        std::cout << "System certificates not available" << std::endl;
        return 2;
    }

    // Similar to above, except we just want the system certificates
    QCA::CertificateCollection systemcerts = QCA::systemStore();

    // this turns the CertificateCollection into a QList of Certificate objects
    certlist = systemcerts.certificates();
}*/

/* switch (menu1())
{
    case 3:
    {
        return 0;
        break;
    }
    case 1://start server
    {
        server = new QTcpServer();
        // mettere qui selezione dell'ip in caso
        if(!server->listen(QHostAddress::LocalHost))
        {
            cout << "Unable to start the server: " << server->errorString().toStdString() << endl;
            return 1;

        }
        cout << "Server is running " << server->serverAddress().toString().toStdString() << ":" << server->serverPort() << endl;

        // waiting for a connection, if not connected wait again
        // it can be changed by put 1000 = -1, but i prefer to
        // have a visual rappresentation
        while(!server->waitForNewConnection(1000))
        {
            cout << ".";
        }
        cout << endl;

        socket = server->nextPendingConnection();

        if(!socket)
        {
            cout << "error on next pending connection" << endl;
        }

        // blocking read call (wait until something readable
        while(1)
        {
            string messaggio = receiveMessageWithSocket(socket);
            cout << "client: " << messaggio << endl;
            sendMessageWithSocket(socket, "ho ricevuto da te questo messaggio: "+messaggio);
        }
        cout << endl;
        break;
    }

    case 2: // start client
    {
        serverIP = insertValidIpAddress("Insert server IP (no hostname)");
        serverPort = insertIntNumber(1, 65535, "Insert server port number (usually 49152 to 65535): ");

        const int Timeout = 5 * 1000;

        socket = new QTcpSocket();
        socket->connectToHost(QString::fromStdString(serverIP), serverPort);

        if (!socket->waitForConnected(Timeout))
        {
            cout << socket->errorString().toStdString();
            return 1;
        }
        cout << "-- SOCKET OPENED --" << endl;

        // blocking read call (wait until something readable
        while(1)
        {
            sendMessageWithSocket(socket, "ti mando un messaggio d\'amore");
            string messaggio = receiveMessageWithSocket(socket);
            cout << "server: " << messaggio << endl;
            system("PAUSE");
        }
        break;
    }
}

*/
/*
cout << endl << endl << endl << "Execution ended... ";
system("pause");

return 0;
}*/

/*QCoreApplication app(argc, argv);
QList<QHostAddress> ipAddressesList;
printPresentation();
ipAddressesList = QNetworkInterface::allAddresses();
int j = 0;
vector<string> ipAddressVect;
stringstream messageText;
messageText << "Select witch ip to use: ";
for (int i = 0; i < ipAddressesList.size(); ++i)
{
    if(ipAddressesList.at(i).toIPv4Address())
    {
        if((int)ipAddressVect.size()>= j)
        {
            ipAddressVect.resize(j+1);
        }
        ipAddressVect.at(j) = ipAddressesList.at(i).toString().toStdString();
        messageText << endl << j << " - " << ipAddressVect.at(j);
        j++;
    }
}

int idSelected = insertIntNumber(0,ipAddressVect.size()-1, messageText.str());
string ipAddress = ipAddressVect.at(idSelected);

cout << endl << "Selected ip: " << idSelected << " - " << ipAddress << endl << endl;

int portNumber = insertIntNumber(49152, 65535, "Select port number (from 49152 to 65535): ");
cout << endl << "Selected ip and port: " << ipAddress << ":" << portNumber << endl << endl;

QTcpServer server;
if(!server.listen())
{
    cout << "Unable to start the server: " << server.errorString().toStdString() << endl;
}*/

/*QList<QHostAddress> ipAddressesList = QNetworkInterface::allAddresses();
cout << "Server is running on this IP's: " << endl;
for (int i = 0; i < ipAddressesList.size(); ++i)
{
    cout << ipAddressesList.at(i).toString().toStdString() << endl;
}*/


/*

            if(!socket->write(QString("scrivo sul socket \n").toUtf8()))
            {
               cout << "error: socket unwritable"  << endl;
            }

            socket->flush();

            socket->waitForReadyRead(10000);

            if(!socket->write(QString("scrivo sul socket2 \n").toUtf8()))
            {
               cout << "error: socket unwritable"  << endl;
            }

            socket->flush();*/

/*
string intToString(int number)
{
    stringstream messageText;
    messageText << number;
    string numberString;
    messageText >> numberString;
    return numberString;
}
*/


/*
string insertValidIpAddress(string testo)
{
    string input;
    bool valid = false;
    while(!valid)
    {
        cout << testo << endl;
        cin >> input;
        QHostAddress address(QString::fromStdString(input));
        if (QAbstractSocket::IPv4Protocol == address.protocol() || QAbstractSocket::IPv6Protocol == address.protocol())
            valid = true;
        else
            cout << endl << "not a valid ip address " << endl << endl;
    }
    return input;
}

int menu1()
{
    stringstream messageText;
    messageText << "Select what to do:" << endl
    << "1- Start server" << endl
    << "2- Start client" << endl
    << "3- Exit" << endl;
    return insertIntNumber(1, 3, messageText.str());
}

int sendMessageWithSocket(QTcpSocket* socket, string message)
{
    if(!socket->write(QString::fromStdString(message).toUtf8()))
    {
       //cout << "error: socket unwritable"  << endl;
       return 1;
    }
    socket->flush();
    // blocking call
    socket->waitForBytesWritten(-1);
    return 0;
}

int sendArrayWithSocket(QTcpSocket* socket, QByteArray array)
{
    if(!socket->write(array))
    {
       //cout << "error: socket unwritable"  << endl;
       return 1;
    }
    socket->flush();
    // blocking call
    socket->waitForBytesWritten(-1);
    return 0;
}

string receiveMessageWithSocket(QTcpSocket* socket)
{
    //blocking wait
    while(!socket->waitForReadyRead(-1));
    //read from socket
    QString socketMessage = QString::fromUtf8(socket->readAll());
    return socketMessage.toStdString();
}

QByteArray receiveArrayWithSocket(QTcpSocket* socket)
{
    //blocking wait
    while(!socket->waitForReadyRead(-1));
    //read from socket
    QByteArray array = socket->readAll();
    return array;
}
*/



// clear message exchange non multi
/*
while(server.getStatus() == STATUS_KEY_EXCHANGED)
{
    string clearMessage;
    server.receiveBlockingMessage(&clearMessage);
    cout << "clearMessage: " << clearMessage << endl;
    cout << ">>";
    cout.flush();
    getline(cin,clearMessage);
    if(clearMessage == "EXIT") return 0;
    server.sendBlockingMessage(clearMessage);
}*/
// encrypted message exchange non multi
/*while(server.getStatus() == STATUS_KEY_EXCHANGED)
{
    string clearMessage;
    server.receiveEncryptedBlockingMessage(&clearMessage);
    if(clearMessage == EXIT_STRING)
    {
        cout << "received EXIT command" << endl;
        return 0;
    }
    cout << "clearMessage: " << clearMessage << endl;
    cout << ">>";
    cout.flush();
    getline(cin,clearMessage);
    if(clearMessage == EXIT_STRING)
    {
        cout << "sending EXIT command" << endl;
        server.sendEncryptedBlockingMessage(clearMessage);
        return 0;
    }
    server.sendEncryptedBlockingMessage(clearMessage);
}*/

// clear message exchange single thread
/*
while(client.getStatus() == STATUS_KEY_EXCHANGED)
{
    string clearMessage;
    cout << ">>";
    cout.flush();
    getline(cin,clearMessage);
    if(clearMessage == "EXIT") return 0;
    client.sendBlockingMessage(clearMessage);
    client.receiveBlockingMessage(&clearMessage);
    cout << "clearMessage: " << clearMessage << endl;
}*/
// encrypted message exchange single thread
/*while(client.getStatus() == STATUS_KEY_EXCHANGED)
{
    string clearMessage;
    cout << ">>";
    cout.flush();
    getline(cin,clearMessage);
    if(clearMessage == EXIT_STRING)
    {
        cout << "sending EXIT command" << endl;
        client.sendEncryptedBlockingMessage(clearMessage);
        return 0;
    }
    client.sendEncryptedBlockingMessage(clearMessage);
    client.receiveEncryptedBlockingMessage(&clearMessage);
    if(clearMessage == EXIT_STRING)
    {
        cout << "received EXIT command" << endl;
        return 0;
    }
    cout << "clearMessage: " << clearMessage << endl;
}
return 0;
*/
    /*
    if(cmdOptionExists(argv, argv+argc, "--server")||cmdOptionExists(argv, argv+argc, "-s"))
    {
        // start server, open socket
        NOSTSClientServer server(SERVER_MODE,serverIP, stringToInt(serverPort));
        if(verbose) server.verboseModeOn();
        if(server.getStatus() == STATUS_ERROR)
        {
            cout << server.getTextStatus() << endl;
            return 1;
        }
        cout << "status: " << server.getStatus() << " - " << server.getTextStatus() << endl;

        if(server.loadCACertificateFromFile(CAcert_filename))
        {
            cout << "error load ca certificate" << endl;
            return 1;
        }

        if(server.loadMyCertificateFromFile(Clientcert_filename))
        {
            cout << "error load client certificate" << endl;
            return 1;
        }

        if(server.loadPrivateKey("/home/mellowonpsx/Desktop/cert/bob.key", "password bob.key")) //must be promped
        {
            cout << "error load private key" << endl;
            return 1;
        }

        server.setUpSTS();
        //multithread message exchange
        //start multithread for message income
        pthread_t thread;
        int rc = pthread_create( &thread, NULL, chatMessageIncome, (void *) &server);
        if (rc)
        {
            cerr << "Error on thread" << endl;
            exit(1);
        }
        //non-multithread for message send
        return chatMessageSender(&server);
    }
    else //start client
    {
        NOSTSClientServer client(CLIENT_MODE,serverIP, stringToInt(serverPort));
        if(verbose) client.verboseModeOn();
        if(client.getStatus()==STATUS_ERROR)
        {
            cout << client.getTextStatus() << endl;
            return 1;
        }

        cout << "status: " << client.getStatus() << " - " << client.getTextStatus() << endl;

        if(client.loadCACertificateFromFile(CAcert_filename))
        {
            cout << "error load ca certificate" << endl;
            return 1;
        }

        if(client.loadMyCertificateFromFile(Clientcert_filename))
        {
            cout << "error load client certificate" << endl;
            return 1;
        }

        if(client.loadPrivateKey("/home/mellowonpsx/Desktop/cert/alice.key", "password alice.key")) //must be promped
        {
            cout << "error load private key" << endl;
            return 1;
        }

        client.setUpSTS();

        //multithread message exchange
        //start multithread for message income
        pthread_t thread;
        int rc = pthread_create( &thread, NULL, chatMessageIncome, (void *) &client);
        if (rc)
        {
            cerr << "Error on thread" << endl;
            exit(1);
        }
        //non-multithread for message send
        return chatMessageSender(&client);
    }

    // if reached probably is a problem!!
    return 1;
}
*/
//-!fine codice utile

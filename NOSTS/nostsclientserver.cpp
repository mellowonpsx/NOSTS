#include "nostsclientserver.h"

NOSTSClientServer::NOSTSClientServer(int mode, string serverIP, int serverPort, bool isVerbose)
{
    verbose = isVerbose;
    status = STATUS_NONE;
    QCA::init(); // init secure array and other functions, it's mandatory for use QCA
    OPENSSL_init();

    if(mode == SERVER_MODE)
    {
        isServer = true;
        if(TCPServerStart(serverIP, serverPort))
        {
            // error happends
            return;
        }
    }

    if(mode == CLIENT_MODE)
    {
        isServer = false;
        if(TCPClientStart(serverIP, serverPort))
        {
            // error happends
            return;
        }
    }
}

int NOSTSClientServer::TCPServerStart(string serverIP, int serverPort)
{
    server = new QTcpServer();

    if(!(serverPort > 0 && serverPort <= 65535))
    {
        status = STATUS_ERROR;
        if(verbose) cerr << "Invalid port number: " << serverPort << endl;
        return 1;
    }

    QHostAddress serverIPAddress;
    serverIPAddress.setAddress(serverIP.c_str());
    if(!server->listen(serverIPAddress, serverPort))
    {
        status = STATUS_ERROR;
        if(verbose) cerr << "Unable to start the server: " << server->errorString().toStdString() << endl;
        return 1;        
    }

    // wait until new connection "infinite"
    server->waitForNewConnection(-1);
    socket = server->nextPendingConnection();

    if(!socket)
    {
        status = STATUS_ERROR;
        if(verbose) cerr << "error on next pending connection" << endl;
        return 1;
    }

    // all ok
    status = STATUS_CONNECTED;
    return 0;
}

int NOSTSClientServer::TCPClientStart(string serverIP, int serverPort)
{
    if(!(serverPort > 0 && serverPort <= 65535))
    {
        status = STATUS_ERROR;
        if(verbose) cerr << "Invalid port number: " << serverPort << endl;
        return 1;
    }

    const int Timeout = 5 * 1000; // 5000ms

    socket = new QTcpSocket();

    socket->connectToHost(serverIP.c_str(), serverPort);

    if (!socket->waitForConnected(Timeout))
    {
        status = STATUS_ERROR;
        if(verbose) cerr << socket->errorString().toStdString() << endl;
        return 1;
    }
    // all ok
    status = STATUS_CONNECTED;
    return 0;
}

int NOSTSClientServer::receiveBlockingMessage(string *receivedMessage)
{
    // STATUS_CONNECTED is the minimum state necessary for send and receive clear message
    if(status<STATUS_CONNECTED) return 1;
    //blocking wait
    //read from socket
    while(!socket->waitForReadyRead(-1));
    socket->flush();
    //copy message to string
    receivedMessage->clear();
    receivedMessage->append(socket->readAll().constData());
    return 0;
}

int NOSTSClientServer::sendBlockingMessage(string messageToSend)
{
    // STATUS_CONNECTED is the minimum state necessary for send and receive clear message
    if(status<STATUS_CONNECTED) return 1;

    if(!socket->write(messageToSend.c_str()))
    {

        status = STATUS_ERROR;
        if(verbose) cerr << "error: socket unwritable"  << endl;
        if(verbose) cerr << "caused by string: " << messageToSend << endl;
        return 1;
    }
    socket->flush();
    // blocking call
    socket->waitForBytesWritten(-1);
    return 0;
}

int NOSTSClientServer::receiveEncryptedBlockingMessage(string *receivedMessage)
{
    // STATUS_KEY_EXCHANGED is the minimum state necessary for send and receive encrypted message
    if(status<STATUS_KEY_EXCHANGED)
    {
        if(verbose) cerr << "Need mutual auth and key exchange to send and receive encrypted message" << endl;
        return 1;
    }
    string encryptedMessage;
    receiveBlockingMessage(&encryptedMessage);
    if(verbose) cout << "RECEIVED encryptedMessage: " << encryptedMessage << endl;
    QByteArray arrayReceived = QByteArray::fromHex(encryptedMessage.c_str());
    string decriptedMessage;
    chipher->decode(arrayReceived, &decriptedMessage);
    //copy message to string
    receivedMessage->clear();
    receivedMessage->append(decriptedMessage);
    return 0;
}

int NOSTSClientServer::sendEncryptedBlockingMessage(string messageToSend)
{
    // STATUS_KEY_EXCHANGED is the minimum state necessary for send and receive encrypted message
    if(status<STATUS_KEY_EXCHANGED)
    {
        if(verbose) cerr << "Need mutual auth and key exchange to send and receive encrypted message" << endl;
        return 1;
    }
    QByteArray arrayToSend;
    chipher->encode(messageToSend, &arrayToSend);
    string encryptedMessageToSend = arrayToSend.toHex().constData();
    if(verbose) cout << "SENDING EncryptedMessage: " << encryptedMessageToSend << endl;
    sendBlockingMessage(encryptedMessageToSend);
    return 0;
}

int NOSTSClientServer::loadCACertificateFromFile(string filename)
{
    if(status<STATUS_CONNECTED) return 1;
    caCert = QCA::Certificate(filename.c_str());
    if(caCert.isNull())
    {
        status = STATUS_CA_CERTIFICATE_LOADED -1;
        return 1;
    }
    else
    {
        if(!caCert.isCA())
        {
            status = STATUS_CA_CERTIFICATE_LOADED -1;
            return 1;
        }
    }
    // all ok
    status = STATUS_CA_CERTIFICATE_LOADED;
    return 0;
}

int NOSTSClientServer::loadMyCertificateFromFile(string filename)
{
    if(status<STATUS_CA_CERTIFICATE_LOADED) return 1;
    myCert =  QCA::Certificate(filename.c_str());
    if(myCert.isNull())
    {
        status = STATUS_MY_CERTIFICATE_LOADED -1;
        return 1;
    }
    else
    {
        if(!caCert.isIssuerOf(myCert))
        {
            status = STATUS_MY_CERTIFICATE_LOADED -1;
            return 1;
        }
    }
    // all ok
    status = STATUS_MY_CERTIFICATE_LOADED;
    return 0;
}

int NOSTSClientServer::loadPrivateKey(string filename, QCA::SecureArray passPhrase)
{
    if(status<STATUS_MY_CERTIFICATE_LOADED) return 1;
    myPrivateKey = QCA::PrivateKey(filename.c_str(), passPhrase);
    if(myPrivateKey.isNull())
    {
        status = STATUS_PRIVATE_CERTIFICATE_LOADED - 1;
        return 1;
    }
    // all ok
    status = STATUS_PRIVATE_CERTIFICATE_LOADED;
    return 0;
}

int NOSTSClientServer::setUpSTS()
{
    if(status<STATUS_PRIVATE_CERTIFICATE_LOADED) return 1;
    if(isServer) return setUpSTSServer();
    return setUpSTSClient();
}

int NOSTSClientServer::setUpSTSServer()
{
    BIGNUM *G = BN_new();
    BIGNUM *P = BN_new();
    BIGNUM *A = BN_new();
    BIGNUM *G_A = BN_new();
    BIGNUM *G_B = BN_new();
    BIGNUM *K_EFF = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    // g is usually 2 or 5
    if(!BN_dec2bn(&G,"2"))
    {
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating G" << endl;
        return 1;
    }

    // p in a random (big) prime number
    if(!BN_generate_prime_ex(P,BITLENGHT_P,1,NULL,NULL,NULL))
    {
        // errore
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating P" << endl;
        return 1;
    }

    // a in a random (big) prime number
    if(!BN_generate_prime_ex(A,BITLENGHT_Q,1,NULL,NULL,NULL))
    {
        // errore
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating A" << endl;
        return 1;
    }

    // calculate A = g^a mod p
    //BN_mod_exp() computes a to the p-th power modulo m (r=a^p % m).
    if(!BN_mod_exp(G_A,G,A,P,ctx))
    {
        // errore
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating G_A" << endl;
        return 1;
    }

    // Send: g,p,A
    stringstream messagestream;

    messagestream << BN_bn2hex(G) << endl << BN_bn2hex(P) << endl << BN_bn2hex(G_A) << endl;
    if(verbose) cout << "SENDING: " << messagestream.str() << endl;
    sendBlockingMessage(messagestream.str());
    //receive B, CERT_b, Encript_k(Sign_b(g^b,g^a));
    string message;
    receiveBlockingMessage(&message);
    if(verbose) cout << "RECIEVED: " << message << endl;

    messagestream.flush(); //flush
    messagestream.clear(); //clear
    messagestream.str(std::string()); //initialize to empty

    messagestream << message;

    string g_b,itsCertString, enc_signature;
    messagestream >> g_b;
    messagestream >> itsCertString;
    messagestream >> enc_signature;

    BN_hex2bn(&G_B, g_b.c_str());

    //calculate K = g^b^a mod p
    if(!BN_mod_exp(K_EFF,G_B,A,P,ctx))
    {
        // errore
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating K_EFF" << endl;
        return 1;
    }

    if(verbose) cout << "Keylenght: "<< BN_num_bits(K_EFF) << "bit" << endl;

    QCA::SecureArray ephimeralKey = BN_bn2hex(K_EFF);
    K = QCA::SymmetricKey(ephimeralKey);
    chipher = new EncDec(ephimeralKey);

    QByteArray receivedEncryptedSignature = QByteArray::fromHex(enc_signature.c_str());
    string decriptedSignature;
    //QCA::SecureArray decriptedSignature;
    if(chipher->decode(receivedEncryptedSignature, &decriptedSignature))
    {
        if(verbose) cerr << "Error on decode" << endl;
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }

    // put certB in certificate
    // verify that certB has signed G_BA
    QCA::ConvertResult certConvRes;
    itsCert = QCA::Certificate::fromPEM(QByteArray::fromHex(itsCertString.c_str()), &certConvRes);
    if (certConvRes != QCA::ConvertGood )
    {
        if(verbose) cerr << "Sorry, could not import itsCert certificate" << endl;
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }
    else
    {
        if(!caCert.isIssuerOf(itsCert))
        {
            if(verbose) cerr << "CA certificate is not an issuer of itsCert certificate" << endl;
            status = STATUS_KEY_EXCHANGED -1;
            return 1;
        }
    }

    string G_BA;
    G_BA += BN_bn2hex(G_B);
    G_BA += BN_bn2hex(G_A);

    QCA::MemoryRegion dataInSign = G_BA.c_str();

    if(verbose) cout << "GENERATING dataInSign: " << dataInSign.constData() << endl;

    QCA::PublicKey itsPublicKey = itsCert.subjectPublicKey();
    if(!itsPublicKey.canVerify())
    {
        if(verbose) cerr << "Error with myCert public key" << endl;
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }
    else
    {
        if (!itsPublicKey.verifyMessage(dataInSign, QByteArray::fromHex(decriptedSignature.c_str()), itsCert.signatureAlgorithm()))
        {
            if(verbose) cerr << "Error with signature" << endl;
            status = STATUS_KEY_EXCHANGED -1;
            return 1;
        }
    }

    //B is authenticated

    //prepare to send CERT_a, Encrypt_keff(Sign_a(g^a,g^b));
    string G_AB;
    G_AB += BN_bn2hex(G_A);
    G_AB += BN_bn2hex(G_B);

    QCA::MemoryRegion dataToSign = G_AB.c_str();

    if(verbose) cout << "GENERATING dataToSign: " << dataToSign.constData() << endl;

    QByteArray signature = myPrivateKey.signMessage(dataToSign, myCert.signatureAlgorithm());
    QByteArray encryptedSignature;
    if(chipher->encode(signature.toHex().constData(), &encryptedSignature))
    {
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }

    //send CERT_A, Encrypt_keff(Sign_a(g^a,g^b));
    messagestream.flush(); //flush
    messagestream.clear(); //clear
    messagestream.str(std::string()); //initialize to empty

    messagestream << myCert.toPEM().toAscii().toHex().constData() << endl << encryptedSignature.toHex().constData() << endl;
    if(verbose) cout << "SENDING: " << messagestream.str() << endl;
    sendBlockingMessage(messagestream.str());

    status = STATUS_KEY_EXCHANGED;

    if(verbose) cout << "Mutual auth completed" << endl;

    return 0;
}

int NOSTSClientServer::setUpSTSClient()
{
    BIGNUM *G = BN_new();
    BIGNUM *P = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *G_A = BN_new();
    BIGNUM *G_B = BN_new();
    BIGNUM *K_EFF = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Receive: g,p,A
    string message;
    receiveBlockingMessage(&message);
    if(verbose) cout << "RECIEVED: " << message << endl;
    stringstream messagestream;
    messagestream << message;
    string g,p,g_a;
    messagestream >> g;
    messagestream >> p;
    messagestream >> g_a;
    BN_hex2bn(&G, g.c_str());
    BN_hex2bn(&P, p.c_str());
    BN_hex2bn(&G_A, g_a.c_str());

    // B is a random integer number
    if(!BN_generate_prime_ex(B,BITLENGHT_Q,1,NULL,NULL,NULL))
    {
        // errore
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating B" << endl;
        return 1;
    }

    // calculate G_B = G^B mod P
    if(!BN_mod_exp(G_B,G,B,P,ctx))
    {
        // errore
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating G_B" << endl;
        return 1;
    }

    //calculate K = g^a^b mod p
    if(!BN_mod_exp(K_EFF,G_A,B,P,ctx))
    {
        // errore
        status = STATUS_KEY_EXCHANGED -1;
        if(verbose) cerr << "error generating K_EFF" << endl;
        return 1;
    }

    //prepare to send B, CERT_b, Encrypt_keff(Sign_b(g^b,g^a));
    string G_BA;
    G_BA += BN_bn2hex(G_B);
    G_BA += BN_bn2hex(G_A);

    if(verbose) cout << "Keylenght: "<< BN_num_bits(K_EFF) << "bit" << endl;

    QCA::SecureArray ephimeralKey = BN_bn2hex(K_EFF);
    K = QCA::SymmetricKey(ephimeralKey);
    chipher = new EncDec(ephimeralKey);

    QCA::MemoryRegion dataToSign = G_BA.c_str();

    if(verbose) cout << "GENERATING dataToSign: " << dataToSign.constData() << endl;

    QByteArray signature = myPrivateKey.signMessage(dataToSign, myCert.signatureAlgorithm());

    QByteArray encryptedSignature;
    if(chipher->encode(signature.toHex().constData(), &encryptedSignature))
    {
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }

    //send B, CERT_b, Encrypt_keff(Sign_b(g^b,g^a));
    messagestream.flush(); //flush
    messagestream.clear(); //clear
    messagestream.str(std::string()); //initialize to empty

    messagestream << BN_bn2hex(G_B) << endl << myCert.toPEM().toAscii().toHex().constData() << endl << encryptedSignature.toHex().constData() << endl;
    if(verbose) cout << "SENDING: " << messagestream.str() << endl;
    sendBlockingMessage(messagestream.str());

    //receive CERT_A, Encript_k(Sign_a(g^a,g^b));
    receiveBlockingMessage(&message);
    if(verbose) cout << "RECIEVED: " << message << endl;

    messagestream.flush(); //flush
    messagestream.clear(); //clear
    messagestream.str(std::string()); //initialize to empty

    messagestream << message;

    string itsCertString, enc_signature;
    messagestream >> itsCertString;
    messagestream >> enc_signature;

    QByteArray receivedEncryptedSignature = QByteArray::fromHex(enc_signature.c_str());
    string decriptedSignature;
    if(chipher->decode(receivedEncryptedSignature, &decriptedSignature))
    {
        if(verbose) cerr << "Error on decode" << endl;
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }

    // put certA in certificate
    // verify that certA has signed G_AB
    QCA::ConvertResult certConvRes;
    itsCert = QCA::Certificate::fromPEM(QByteArray::fromHex(itsCertString.c_str()), &certConvRes);
    if (certConvRes != QCA::ConvertGood )
    {
        if(verbose) cerr << "Sorry, could not import itsCert certificate" << endl;
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }
    else
    {
        if(!caCert.isIssuerOf(itsCert))
        {
            if(verbose) cerr << "CA certificate is not an issuer of itsCert certificate" << endl;
            status = STATUS_KEY_EXCHANGED -1;
            return 1;
        }
    }

    string G_AB;
    G_AB += BN_bn2hex(G_A);
    G_AB += BN_bn2hex(G_B);

    QCA::MemoryRegion dataInSign = G_AB.c_str();

    if(verbose) cout << "GENERATING dataInSign: " << dataInSign.constData() << endl;

    QCA::PublicKey itsPublicKey = itsCert.subjectPublicKey();
    if(!itsPublicKey.canVerify())
    {
        if(verbose) cerr << "Error with myCert public key" << endl;
        status = STATUS_KEY_EXCHANGED -1;
        return 1;
    }
    else
    {
        if (!itsPublicKey.verifyMessage(dataInSign, QByteArray::fromHex(decriptedSignature.c_str()), itsCert.signatureAlgorithm()))
        {
            if(verbose) cerr << "Error with signature" << endl;
            status = STATUS_KEY_EXCHANGED -1;
            return 1;
        }
    }

    // mutual auth
    status = STATUS_KEY_EXCHANGED;

    if(verbose) cout << "Mutual auth completed" << endl;

    return 0;
}

int NOSTSClientServer::getStatus()
{
    return status;
}

void NOSTSClientServer::flushErrors()
{
    status = STATUS_NONE;
    if(verbose) cerr.flush();
}

string NOSTSClientServer::getTextStatus()
{
    stringstream message;

    if(status == STATUS_ERROR)
    {
        message << "There are errors";
        return message.str();
    }

    if(status == STATUS_NONE)
    {
        message << "Invalid Client/Server status";
        return message.str();
    }

    if(status == STATUS_CONNECTED)
    {
        if(isServer) message << "Server is running " << server->serverAddress().toString().toStdString() << ":" << server->serverPort() << endl;
        message << "There is an open socket from " << socket->localAddress().toString().toStdString() << ":" << socket->localPort() << " to " << socket->peerAddress().toString().toStdString() << ":" << socket->peerPort() << endl;
        return message.str();
    }
    // never reached
    return message.str();
}

void NOSTSClientServer::verboseModeOn()
{
    verbose = true;
}

void NOSTSClientServer::verboseModeOff()
{
    verbose = false;
}

string NOSTSClientServer::getMyCertificateName()
{
    if(status == STATUS_MY_CERTIFICATE_LOADED) return myCert.commonName().toStdString();
    else return "";
}

string NOSTSClientServer::getItsCertificateName()
{
    if(status == STATUS_KEY_EXCHANGED) return itsCert.commonName().toStdString();
    else return "";
}

#ifndef NOSTSCLIENTSERVER_H
#define NOSTSCLIENTSERVER_H

#include <QtNetwork>
#include <iostream>
#include <sstream>
#include <QtCrypto>
#include <QtCrypto/qca_tools.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include "encdec.h"

#define SERVER_MODE 1
#define CLIENT_MODE 2

// FFC Domain Parameter Generation
//http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf
#define BITLENGHT_P 1024
#define BITLENGHT_Q 160
//#Minimum bit length of the hash function output 160
//Minimum MAC key size (for use in key confirmation) 80
//Minimum MacLen (for use in key confirmation) 80

#define STATUS_ERROR 0
#define STATUS_NONE 1
#define STATUS_CONNECTED 2 //connected is enought for clear message exchange
#define STATUS_CA_CERTIFICATE_LOADED 3
#define STATUS_MY_CERTIFICATE_LOADED 4
#define STATUS_PRIVATE_CERTIFICATE_LOADED 5
//#define STATUS_ITS_CERTIFICATE_LOADED 6 -> loaded during key exchange
#define STATUS_KEY_EXCHANGED 6

using namespace std;

class NOSTSClientServer
{
    private:
        bool isServer;
        QTcpServer* server;
        QTcpSocket* socket;
        // Authority certificate
        QCA::Certificate caCert;
        // My certificate
        QCA::Certificate myCert;
        // The other side of socket certificate
        QCA::Certificate itsCert;
        // My PrivateCert, used for sign
        QCA::PrivateKey myPrivateKey;
        // SymmetricKey container
        QCA::SymmetricKey K;
        EncDec *chipher;
        // for verbose mode
        bool verbose;

        // private methods
        int TCPServerStart(string serverIP, int serverPort);
        int TCPClientStart(string serverIP, int serverPort);
        int setUpSTSServer();
        int setUpSTSClient();
        int status;
    public:
        // initialize server and open socket
        NOSTSClientServer(int mode, string serverIP, int serverPort, bool isVerbose = false);
        int getStatus();
        string getTextStatus();
        void flushErrors();
        // send and receive clear message with blocking call
        int receiveBlockingMessage(string *receivedMessage);
        int sendBlockingMessage(string messageToSend);        
        int receiveEncryptedBlockingMessage(string *receivedMessage);
        int sendEncryptedBlockingMessage(string messageToSend);
        // load certificate
        int loadCACertificateFromFile(string filename);
        int loadMyCertificateFromFile(string filename);
        int loadPrivateKey(string filename, QCA::SecureArray passPhrase); // use secure array limitate memory sniffs
        // ephimeral key initialization
        int setUpSTS();
        // load verbose mode
        void verboseModeOn();
        void verboseModeOff();
        // name of client and server
        string getMyCertificateName();
        string getItsCertificateName();
};

#endif // NOSTSCLIENTSERVER_H

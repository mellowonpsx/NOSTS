#ifndef ENCDEC_H
#define ENCDEC_H

#include <QtCrypto>

class EncDec
{
    private:
        // Encoder
        QCA::Cipher *encoder;
        // Decoder
        QCA::Cipher *decoder;
        // Base64 encoder
        QCA::Base64 *encoder64;
        // Base64 decoder
        QCA::Base64 *decoder64;
        // SymmetricKey
        QCA::SymmetricKey K;
    public:
        EncDec(QCA::SecureArray ephimeralKey);
        //QByteArray encode(std::string textToEncode);
        //std::string decode(QByteArray arrayToDecrypt);
        int encode(std::string textToEncode, QByteArray *dest);
        int decode(QByteArray arrayToDecrypt, std::string *dest);
        //int decode(QByteArray arrayToDecrypt, QCA::SecureArray *dest);
};
#endif // ENCDEC_H

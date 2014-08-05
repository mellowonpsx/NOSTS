#include "encdec.h"

#define DEFAULT_IV "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456"

#include <iostream>

EncDec::EncDec(QCA::SecureArray ephimeralKey)
{
    encoder64 = new QCA::Base64(QCA::Encode);
    decoder64 = new QCA::Base64(QCA::Decode);
    K = QCA::SymmetricKey(ephimeralKey);
    QCA::InitializationVector iv(QCA::SecureArray(DEFAULT_IV));

    encoder = new QCA::Cipher(QString("aes256"),
                               QCA::Cipher::CBC,
                             QCA::Cipher::PKCS7,
                                    QCA::Encode,
                                              K,
                                            iv);

    decoder = new QCA::Cipher(QString("aes256"),
                               QCA::Cipher::CBC,
                             QCA::Cipher::PKCS7,
                                    QCA::Decode,
                                              K,
                                            iv);
}

int EncDec::encode(std::string textToEncode, QByteArray *dest)
{
    encoder->clear();
    QCA::MemoryRegion dataToEncrypt = QCA::MemoryRegion(textToEncode.c_str());
    QCA::SecureArray dataEncrypted = encoder->update(dataToEncrypt);
    QCA::SecureArray dataEncryptedFinalBlock = encoder->final();
    dataEncrypted.append(dataEncryptedFinalBlock);
    if (!encoder->ok())
    {
        std::cerr << "Error on encryption" << std::endl;
        return 1;
    }
    dest->clear();
    dest->append(dataEncrypted.toByteArray());
    return 0;
}

int EncDec::decode(QByteArray arrayToDecrypt, std::string *dest)
{
    decoder->clear();
    QCA::MemoryRegion dataToDecrypt = QCA::MemoryRegion(arrayToDecrypt);
    QCA::SecureArray dataDecrypted = decoder->update(dataToDecrypt);
    QCA::SecureArray dataDecryptedFinalBlock = decoder->final();
    dataDecrypted.append(dataDecryptedFinalBlock);
    if (!decoder->ok())
    {
        std::cerr << "Error on decryption" << std::endl;
        return 1;
    }
    dest->clear();
//    std::cout << "messagelenght: " << dataDecrypted.size() << std::endl;
    if(dataDecrypted.size()>0) dest->append(dataDecrypted.constData());
    return 0;
}

/*int EncDec::decode(QByteArray arrayToDecrypt, QCA::SecureArray *dest)
{
    encoder->clear();
    QCA::MemoryRegion dataToDecrypt = QCA::MemoryRegion(arrayToDecrypt);
    QCA::SecureArray dataDecrypted = decoder->update(dataToDecrypt);
    QCA::SecureArray dataDecryptedFinalBlock = decoder->final();
    dataDecrypted.append(dataDecryptedFinalBlock);
    if (!decoder->ok())
    {
        std::cerr << "Error on decryption" << std::endl;
        return 1;
    }
    dest->clear();
    dest->append(dataDecrypted);
    return 0;
}*/

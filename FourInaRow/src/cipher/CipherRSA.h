
#ifndef FOURINAROW_CIPHERRSA_H
#define FOURINAROW_CIPHERRSA_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include "../utility/Message.h"
#include "../utility/Converter.h"
#include <unordered_map>

using namespace utility;

namespace cipher {

    struct keyStruct{
        string username;
        EVP_PKEY* pubKey;
    };

    class CipherRSA {
        private:
            EVP_PKEY* myPrivKey = nullptr;
            EVP_PKEY* myPubKey = nullptr;
            EVP_PKEY* advPubKey = nullptr;
            EVP_PKEY* caKey = nullptr;
            EVP_PKEY* pubServerKey = nullptr;
            std::unordered_map<string,EVP_PKEY*> keyArchive;

            unsigned char* makeSignature( unsigned char* fields, unsigned int& len, EVP_PKEY* privKey  );
            bool verifySignature( unsigned char* msg, unsigned char* signature , int msgLen, int len, EVP_PKEY* pubKey );
            bool verifyCertificate(X509* certificate);

        public:

            CipherRSA( string username, string password );                            //  costructor for a client
            CipherRSA( string serverName, string password, string users[], int len ); //  costructor for the server
            ~CipherRSA();
            bool sign( Message *message );
            bool clientVerifySignature( Message message , bool server );
            bool serverVerifySignature( Message message, string username );

            bool setAdversaryKey( EVP_PKEY* signature );
            void unsetAdversaryKey();
            bool loadUserKey( string username );
            bool removeUserKey( string username );
            EVP_PKEY* getUserKey( string username );
            EVP_PKEY extractServerKey( unsigned char* certificate , int len );
            static bool test();


    };
}

#endif //FOURINAROW_CIPHERRSA_H

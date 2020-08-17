
#ifndef FOURINAROW_CIPHERRSA_H
#define FOURINAROW_CIPHERRSA_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <cstring>
#include "../utility/Message.h"

using namespace utility;

namespace cipher {
    class CipherRSA {
        private:
            EVP_PKEY* pubKey;
            EVP_PKEY* privKey;

            EVP_PKEY* advKey;
            EVP_PKEY* caKey;

            unsigned char* makeSignature( unsigned char* fields, int& len, EVP_PKEY* privKey  );
            bool verifySignature( unsigned char* msg, unsigned char* signature , int msgLen, int len, EVP_PKEY* pubKey );

        public:
            CipherRSA( string username, string password );                            //  costructor for a client
            CipherRSA( string serverName, string password, string mySqlUsername, string mySqlPassword );  //  costructor for the server
            ~CipherRSA();
            void sign( Message *message );
            bool clientVerifySignature( Message message , bool server );
            bool serverVerifySignature( Message message, string username );
            bool verifyCertificate();
            bool setAdversaryKey( EVP_PKEY* signature );
            void unsetAdversaryKey();


    };
}

#endif //FOURINAROW_CIPHERRSA_H


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

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   CIPHER RSA                                      //
    //    The class is in charge of:                                                     //
    //       - generate/verify signatures                                                //
    //       - store needed keys in a transparent way                                    //
    //       - verify server certificate validity                                        //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    struct keyStruct{

        string username;
        EVP_PKEY* pubKey;

    };

    class CipherRSA {

        private:
            //  CLIENT VARIABLES
            EVP_PKEY* advPubKey = nullptr;
            EVP_PKEY* pubServerKey;

            //  SERVER VARIABLES
            std::unordered_map<string,EVP_PKEY*> keyArchive;
            unsigned char* serverCertificate = nullptr;
            unsigned int lenServerCertificate;

            //  COMMON VARIABLES
            EVP_PKEY* myPrivKey = nullptr;
            EVP_PKEY* myPubKey = nullptr;
            bool server = false;

            unsigned char* makeSignature( unsigned char* fields, unsigned int& len, EVP_PKEY* privKey  );                 //  GENERATE A SIGNATURE FROM A COMPRESS FORM OF A MESSAGE
            static bool verifySignature( unsigned char* msg, unsigned char* signature , int msgLen, int len, EVP_PKEY* pubKey ); //  VERIFY A SIGNATURE OF A MESSAGE
            static bool verifyCertificate(X509* certificate);                                                                    //  VERIFY THE VALIDITY OF A CERTIFICATE

        public:

            CipherRSA( string username, string password , bool server );
            ~CipherRSA();

            //  COMMON UTILITIES
            bool sign( Message *message );                 //  GENERATE AND PUT A SIGNATURE IN A MESSAGE CLASS
            static bool test();

            //  SERVER UTILITIES
            bool loadUserKey( string username );                               //  LOAD THE KEY OF THE USER INTO THE KEY ARCHIVE
            bool removeUserKey( string username );                             //  REMOVE THE KEY OF THE USER FROM THE ARCHIVE
            EVP_PKEY* getUserKey( string username );                           //  TAKE THE KEY OF THE USER FROM THE ARCHIVE
            bool serverVerifySignature( Message message, string username );    //  VERIFY THE SIGNATURE OF A MESSAGE[SERVER]
            NetMessage* getServerCertificate();

            //  CLIENT UTILITIES
            bool setAdversaryKey( EVP_PKEY* signature );                        //  SET AN ADVERSARY KEY
            void unsetAdversaryKey();                                           //  REMOVE AN ADVERSARY KEY
            static EVP_PKEY* extractServerKey( unsigned char* certificate , int len ); //  EXTRACT A PUBLIC KEY FROM A CERTIFICATE[CERTIFICATE MESSAGE]
            bool extractAdversaryKey( string username, unsigned char* pubKey , int len );        //  EXTRACT ADVERSARY PUBLIC KEY FROM PUBKEY FIELD[GAME_PARAM MESSAGE]
            bool clientVerifySignature( Message message , bool server );        //  VERIFY THE SIGNATURE OF A MESSAGE[CLIENT]
            static bool certificateVerification( Message* message, EVP_PKEY* key );     //  ONLY FOR CERTIFICATE MESSAGE SIGNATURE VERIFICATION
            bool setServerKey( EVP_PKEY* server );                              //  SET SERVER PUBLIC KEY
            EVP_PKEY* getPubKey();                                              //  UTILITY FOR TESTING [TO BE REMOVED]

    };
}

#endif //FOURINAROW_CIPHERRSA_H

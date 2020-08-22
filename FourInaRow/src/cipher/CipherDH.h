
#ifndef FOURINAROW_CIPHERDH_H
#define FOURINAROW_CIPHERDH_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../Logger.h"
#include "../utility/NetMessage.h"
#include <fstream>
#include "CipherHASH.h"
#include "CipherRSA.h"

using namespace utility;

namespace cipher {

    struct SessionKey{
        unsigned char* sessionKey;
        unsigned int sessionKeyLen;
        unsigned char* iv;
        unsigned int ivLen;
    };

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   CIPHER_DH                                        //
    //    The class is in charge of generating session keys. It usage pass throught two  //
    //    phases. The first start with the usage of generatePartialKey() which creates   //
    //    the parameter to exchange with the other peer. Obtained the parameter from the //
    //    other peer with generateSessionKey the class generate a structure which        //
    //    contains all the informations needed from the CipherAES to perform symmetric   //
    //    encryption with a shared session key between the two peers                     //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class CipherDH {
        private:
            EVP_PKEY* ephemeralKey = nullptr;
            DH* get_dh2048_auto();
            SessionKey* generateKeys( unsigned char* value , int len );

        public:
            CipherDH();
            ~CipherDH();
            NetMessage* generatePartialKey();                                      //  GENERATE THE PARAMETER TO EXCHANGE
            SessionKey* generateSessionKey( unsigned char *partialKey, int len );  //  GENERATE THE SESSION PARAMETERS
            void stash();                                                          //  ABORT THE CURRENT SESSION PARAM GENERATION
            static void test();

    };
}


#endif //FOURINAROW_CIPHERDH_H

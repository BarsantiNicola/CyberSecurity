
#ifndef FOURINAROW_CIPHERDH_H
#define FOURINAROW_CIPHERDH_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../Logger.h"
#include "../utility/NetMessage.h"
#include "CipherHASH.h"
#include <fstream>
using namespace utility;

namespace cipher {

    struct SessionKey{
        unsigned char* sessionKey;
        unsigned int sessionKeyLen;
        unsigned char* iv;
        unsigned int ivLen;
    };

    class CipherDH {
        private:
            EVP_PKEY* ephemeralKey = nullptr;
            DH* get_dh2048_auto();

        public:
            CipherDH();
            ~CipherDH();

            NetMessage* generatePartialKey();
            SessionKey* generateSessionKey( unsigned char *partialKey, int len );
            static void test();

    };
}


#endif //FOURINAROW_CIPHERDH_H

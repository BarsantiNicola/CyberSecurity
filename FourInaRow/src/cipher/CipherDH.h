
#ifndef FOURINAROW_CIPHERDH_H
#define FOURINAROW_CIPHERDH_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../Logger.h"
#include "../utility/NetMessage.h"
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
            EVP_PKEY* key = nullptr;
            EVP_PKEY* sessionKey = nullptr;

        public:
            CipherDH(string username, bool server);
            ~CipherDH();

            NetMessage* generatePartialKey( const char* i);
            SessionKey* generateSessionKey( unsigned char *partialKey, int len, const char* i);
            static void test();

    };
}


#endif //FOURINAROW_CIPHERDH_H

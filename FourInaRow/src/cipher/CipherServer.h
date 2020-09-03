
#ifndef FOURINAROW_CIPHERSERVER_H
#define FOURINAROW_CIPHERSERVER_H
#include "CipherRSA.h"
#include "CipherDH.h"
#include "CipherAES.h"
#include "../Logger.h"
#include "../utility/Message.h"
#include "../utility/NetMessage.h"

using namespace utility;

namespace cipher {

    class CipherServer {

        private:
            CipherRSA* rsa;
            CipherDH*  dh;
            CipherAES* aes;

        public:
            CipherServer();
            ~CipherServer();
            bool toSecureForm( Message* message, SessionKey* aesKey );
            bool fromSecureForm( Message* message , string username , SessionKey* aesKey );
            NetMessage* getServerCertificate();
            SessionKey* getSessionKey( unsigned char* param, unsigned int len );
            NetMessage* getPartialKey();
            NetMessage* getPubKey( string username );
    };
}


#endif //FOURINAROW_CIPHERSERVER_H

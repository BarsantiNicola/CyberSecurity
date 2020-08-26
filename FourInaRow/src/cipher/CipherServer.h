
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
            Message* toSecureForm( MessageType type , Message* message );
            Message* fromSecureForm( Message* message , string username );
            Message* setServerCertificate( Message* message );
            SessionKey* getSessionKey( Message* message);
    };
}


#endif //FOURINAROW_CIPHERSERVER_H


#ifndef FOURINAROW_USERINFORMATION_H
#define FOURINAROW_USERINFORMATION_H

#include <iostream>
#include "../utility/NetMessage.h"
#include "../cipher/CipherDH.h"

using namespace std;

namespace server {

    enum UserStatus{

        CONNECTED,
        LOGGED,
        WAIT_MATCH,
        PLAY

    };

    class UserInformation{
        private:
            string username;
            cipher::SessionKey sessionKey;
            UserStatus status;
            int* nonce;
            string ip;

        public:
            UserInformation( string username , string ip );
            UserInformation( string username, UserStatus status ,string ip,  cipher::SessionKey key );
            string getUsername();
            bool setSessionKey( cipher::SessionKey key );
            cipher::SessionKey getSessionKey();
            void setStatus( UserStatus status );
            UserStatus getStatus();
            void setNonce( int nonce );
            int* getNonce();
            string getIP();

    };

}

#endif //FOURINAROW_USERINFORMATION_H

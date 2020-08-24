
#ifndef FOURINAROW_USERINFORMATION_H
#define FOURINAROW_USERINFORMATION_H

#include <iostream>
#include "../utility/NetMessage.h"
#include "../utility/Information.h"

using namespace std;

namespace server {

    enum UserStatus{

        CONNECTED,
        LOGGED,
        WAIT_MATCH,
        PLAY

    };

    class UserInformation : public utility::Information{
        private:
            string username;
            unsigned char* sessionKey;
            unsigned int len;
            UserStatus status;

        public:
            UserInformation( string username );
            ~UserInformation();
            bool setSessionKey( unsigned char* key , int len );
            utility::NetMessage* getSessionKey();
            void setStatus( UserStatus status );
            UserStatus getStatus();

    };

}

#endif //FOURINAROW_USERINFORMATION_H

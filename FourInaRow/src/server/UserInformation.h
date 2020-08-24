
#ifndef FOURINAROW_USERINFORMATION_H
#define FOURINAROW_USERINFORMATION_H

#include <iostream>
#include "../utility/NetMessage.h"

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
            unsigned char* sessionKey;
            unsigned int len;
            UserStatus status;

        public:
            UserInformation( string username );
            UserInformation( string username, UserStatus status , utility::NetMessage* key );
            ~UserInformation();
            string getUsername();
            bool setSessionKey( unsigned char* key , int len );
            utility::NetMessage* getSessionKey();
            void setStatus( UserStatus status );
            UserStatus getStatus();

    };

}

#endif //FOURINAROW_USERINFORMATION_H


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

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   USER INFORMATION                                //
    //    The class maintans information about a user(socket,username,keys and           //
    //    a status)                                                                      //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class UserInformation{

        private:
            int socket;
            string username;
            cipher::SessionKey* sessionKey;
            UserStatus status;
            int* nonce;

        public:
            UserInformation( int socket, string username  );
            UserInformation( int socket, string username, UserStatus status,  cipher::SessionKey* key, int* nonce );

            bool setSessionKey( cipher::SessionKey* key );
            bool setStatus( UserStatus status );
            void setNonce( int nonce );

            int    getSocket();
            string getUsername();
            cipher::SessionKey* getSessionKey();
            UserStatus* getStatus();
            int* getNonce();

    };

}

#endif //FOURINAROW_USERINFORMATION_H

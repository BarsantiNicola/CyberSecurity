//
// Created by nico on 24/08/20.
//

#ifndef FOURINAROW_USERREGISTER_H
#define FOURINAROW_USERREGISTER_H

#include "UserInformation.h"
#include "../Logger.h"
#include <vector>
#include "../cipher/CipherDH.h"
#include "../utility/NetMessage.h"

namespace server {

    class UserRegister{

        private:
            vector<UserInformation> userRegister;

        public:
            bool addUser( int socket , string username );

            bool setSessionKey( string username , cipher::SessionKey* key );
            bool setNonce( string username , int nonce );
            bool setLogged( string username , cipher::SessionKey* key );
            bool setPlay( string username );
            bool setWait( string username );
            bool setDisconnected( string username );

            bool removeUser( string username );
            bool removeUser( int socket );

            bool has( int socket );
            bool has( string username );

            cipher::SessionKey* getSessionKey( string username );
            int*        getNonce( string username );
            UserStatus*  getStatus( string username );
            string      getUsername( int socket );
            NetMessage* getUserList();
    };

}


#endif //FOURINAROW_USERREGISTER_H

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
            bool addUser( string username , string IP );
            bool removeUser( string username );
            UserInformation* getUser( string username );
            bool hasUser( string username );
            bool setLogged( string username , cipher::SessionKey key );
            bool setPlay( string username );
            bool setWait( string username );
            int* getUserID( string username );
            NetMessage* getUserList();
            bool setNonce( string username, int nonce );
            int* getNonce( string username );
            string getIP( string username );
            static void test();

    };

}


#endif //FOURINAROW_USERREGISTER_H

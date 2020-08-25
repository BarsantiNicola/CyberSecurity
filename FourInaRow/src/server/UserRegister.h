//
// Created by nico on 24/08/20.
//

#ifndef FOURINAROW_USERREGISTER_H
#define FOURINAROW_USERREGISTER_H

#include "UserInformation.h"
#include "../Logger.h"
#include <vector>

namespace server {

    class UserRegister{

        private:
            vector<UserInformation> userRegister;

        public:
            bool addUser( string username );
            bool removeUser( string username );
            UserInformation* getUser( string username );
            bool hasUser( string username );
            bool setLogged( string username , unsigned char* sessionKey , unsigned int len );
            bool setPlay( string username );
            bool setWait( string username );
            int* getUserID( string username );
            static void test();

    };

}


#endif //FOURINAROW_USERREGISTER_H

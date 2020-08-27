
#ifndef FOURINAROW_CLIENTREGISTER_H
#define FOURINAROW_CLIENTREGISTER_H

#include "ClientInformation.h"
#include "../Logger.h"
#include <vector>
using namespace utility;

namespace server {

    class ClientRegister {

        private:
            vector<ClientInformation> clientRegister;

        public:
            bool   addClient( string ip , int socket );      // ADD NEW CLIENT
            bool   removeClient( int socket );               // REMOVE A CLIENT
            bool   has( int socket );                        // SEARCH IF A SOCKET IS PRESENT
            string getClientNetInformation( int socket );    // RETURN THE CLIENT IP ADDRESS

    };

}


#endif //FOURINAROW_CLIENTREGISTER_H

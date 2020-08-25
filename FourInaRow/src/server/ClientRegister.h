
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
            bool addClient( int clientID , string ip , int socket );
            bool setNonceByID( int clientID , int nonce );
            bool setNonceBySocket( int socket , int nonce );
            int* getNonceByID( int clientID );
            int* getNonceBySocket( int socket );
            bool removeClientBySocket( int socket );
            bool removeClientByID( int clientID );
            bool hasID( int clientID );
            bool hasSocket( int socket );
            ClientInformation* getClientBySocket( int socket );
            ClientInformation* getClientByID( int clientID );

            static void test();

    };

}


#endif //FOURINAROW_CLIENTREGISTER_H

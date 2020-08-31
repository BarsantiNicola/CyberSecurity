
#ifndef FOURINAROW_CLIENTREGISTER_H
#define FOURINAROW_CLIENTREGISTER_H

#include "ClientInformation.h"
#include "../Logger.h"
#include <vector>
using namespace utility;

namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   CLIENT REGISTER                                 //
    //    The class maintans information about the connected clients(socket and ip)      //
    //    It permits easely to add or remove a client basing on its socket and a search  //
    //    into the archive to know if a client is present or get its net address.        //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class ClientRegister {

        private:
            vector<ClientInformation> clientRegister;

        public:
            bool   addClient( string ip , int socket );      // ADD NEW CLIENT
            bool   removeClient( int socket );               // REMOVE A CLIENT
            bool   has( int socket );                        // SEARCH IF A SOCKET IS PRESENT
            string getClientNetInformation( int socket );    // RETURN THE CLIENT IP ADDRESS
            int*   getClientNonce( int socket );
            bool   updateClientNonce( int socket );
            bool   setNonce( int socket , int nonce );

    };

}


#endif //FOURINAROW_CLIENTREGISTER_H

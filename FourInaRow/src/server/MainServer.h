
#ifndef FOURINAROW_MAINSERVER_H
#define FOURINAROW_MAINSERVER_H

#include "ClientRegister.h"
#include "UserRegister.h"
#include "MatchRegister.h"
#include "SQLConnector.h"
#include "../Logger.h"
#include "../utility/Message.h"
#include "../cipher/CipherServer.h"
#include "../utility/ConnectionManager.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

using namespace server;

namespace server {
    class MainServer {

        private:
            ClientRegister clientRegister;
            MatchRegister matchRegister;
            UserRegister userRegister;
            utility::ConnectionManager* manager;
            cipher::CipherServer cipherServer;

            Message* certificateHandler( Message* message );
            Message* loginHandler( Message* message,  int socket );
            Message* keyExchangeHandler( Message* message , string username );
            Message* gameParamHandler( string source , int match , bool step );
            Message* userListHandler( Message* message, string username );
            Message* rankListHandler( Message* message, string username );
            Message* matchListHandler( Message* message );
            Message* acceptHandler( Message* message);
            Message* rejectHandler( Message* message);
            Message* disconnectHandler( Message* message, int matchID);
            Message* logoutHandler( Message* message , string username );
            Message* sendError( string errorMessage );
            Message* closeMatch(int matchID);
            Message* manageMessage( Message* message, int socket );

            Message* userManager(Message* message, string username , int socket );
            Message* matchManager(Message* message, string username );
            Message* waitMessage( int& socket );
            bool sendMessage( Message* message , string username );
            void logoutClient(int socket);
            bool registerClient( int socket, string ip );

        public:
            MainServer( string ipAddr , int port );
            void server();
            static void test();

    };
}


#endif //FOURINAROW_MAINSERVER_H


#ifndef FOURINAROW_MAINSERVER_H
#define FOURINAROW_MAINSERVER_H

#include "ClientRegister.h"
#include "UserRegister.h"
#include "MatchRegister.h"
#include "SQLConnector.h"
#include "../Logger.h"
#include "../utility/Message.h"
#include "../cipher/CipherServer.h"
using namespace server;

namespace server {
    class MainServer {

        private:
            ClientRegister clientRegister;
            MatchRegister matchRegister;
            UserRegister userRegister;
            cipher::CipherServer cipherServer;

            Message* certificateHandler( Message* message );
            Message* loginHandler( Message* message, string ip);
            Message* keyExchangeHandler( Message* message , int matchID, string username );
            Message* gameParamHandler( string source , int match , bool step );
            Message* userListHandler( Message* message);
            Message* rankListHandler( Message* message);
            Message* matchListHandler( Message* message );
            Message* acceptHandler( Message* message);
            Message* rejectHandler( Message* message);
            Message* disconnectHandler( Message* message, int matchID);
            Message* logoutHandler( Message* message , string username );
            Message* errorResponse( string errorMessage );
            Message* closeMatch(int matchID);

        public:
            MainServer( string ipAddr , int port );
            Message* clientManager(Message* message, int socket );
            Message* userManager(Message* message, string username );
            Message* matchManager(Message* message, string username );

    };
}


#endif //FOURINAROW_MAINSERVER_H


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

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   MAIN SERVER                                     //
    //    The class implements a server based on a given ipv4 address and a port.        //
    //    The server wait to receive a message and after sanitization and identification //
    //    of its content it assigns it to service skeleton which generates the correct   //
    //    behavior. The server is based on three register which collect information      //
    //    about the connected clients and a CipherServer class which contains the        //
    //    security routines to be applied during its work.                               //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class MainServer {

        private:
            ClientRegister clientRegister;        //  COLLECTS INFORMATION ABOUT CONNECTED CLIENTS(IPADDR, SOCKET)
            UserRegister userRegister;            //  COLLECTS INFORMATION ABOUT THE LOGGED USERS(NAME,KEYS,STATUS)
            MatchRegister matchRegister;          //  COLLECTS INFORMATION ABOUT THE OPENED MATCHES(PARTECIPANTS, STATUS)
            utility::ConnectionManager* manager;  //  GIVES ROUTINES TO RECEIVE AND SEND MESSAGES INTO NETWORK
            cipher::CipherServer cipherServer;    //  GIVES ROUTINES TO APPLY SECURITY PROTOCOLS

            //  PROTOCOL HANDLERS
            Message* certificateHandler( Message* message , int socket );                           //  MANAGES MESSAGE CERTIFICATE_REQ
            Message* loginHandler( Message* message,  int socket, unsigned int* nonce );                     //  MANAGES MESSAGE LOGIN_REQ
            Message* keyExchangeHandler( Message* message , string username, unsigned int* nonce );          //  MANAGES MESSAGE KEY_EXCHANGE
            Message* userListHandler( Message* message, string username, unsigned int* nonce );              //  MANAGES MESSAGE USER_LIST_REQ
            Message* rankListHandler( Message* message, string username, unsigned int* nonce );              //  MANAGES MESSAGE RANK_LIST_REQ
            Message* logoutHandler( Message* message , string username , int socket, unsigned int* nonce );  //  MANAGES MESSAGE LOGOUT_REQ
            Message* matchHandler( Message* message, string username, unsigned int* nonce );                 //  MANAGES MESSAGE MATCH
            Message* acceptHandler( Message* message , string username, unsigned int* nonce );               //  MANAGES MESSAGE ACCEPT
            Message* rejectHandler( Message* message , string username, unsigned int* nonce );               //  MANAGES MESSAGE REJECT
            Message* withdrawHandler( Message* message, string username, unsigned int* nonce );              //  MANAGES MESSAGE WITHDRAW_REQ
            Message* disconnectHandler( Message* message, string username, unsigned int* nonce );            //  MANAGES MESSAGE DISCONNECT
            Message* gameHandler( Message* message, string username, unsigned int* nonce );                  //  MANAGES MESSAGE GAME

            //  MESSAGE HANDLERS
            Message* manageMessage( Message* message, int socket );                 //  HANDLES MESSAGES AND SENT THEM TO THE CORRECT PROTOCOL
            Message* userManager(Message* message, string username , int socket );  //  HANDLES MESSAGES WHICH INVOLVE ONLY THE USER AND THE SERVER
            Message* matchManager(Message* message, string username, unsigned int* nonce );  //  HANDLES MESSAGES WHICH INVOLVE MANY USERS

            //  ASYNC MESSAGE SENDERS
            bool sendAcceptMessage( string challenger, string challenged, int* socket );  //  SENDS AN ACCEPT MESSAGE
            bool sendRejectMessage( string challenger, string challenged, int* socket );  //  SENDS A REJECT MESSAGE
            bool sendWithdrawMessage( string username, string challenger, int* socket );   //  SENDS A WITHDRAW_REQ MESSAGE
            bool sendDisconnectMessage( string username );              //  SENDS A DISCONNECT MESSAGE
            bool sendGameParam( string username , string source );      //  MANAGES MESSAGE GAME_PARAM

            //  UTILITIES
            void logoutClient(int socket);                              //  SECURE DISCONNECTION OF A CLIENT FROM THE SERVER
            void closeMatch( string username, int matchID );            //  CLOSES A MATCH AND ADVERTICE PARTICIPANTS
            int  generateRandomNonce();                                 //  GENERATES A RANDOM NONCE TO BE USED BY CLIENTS
            bool sendMessage( Message* message, int socket );           //  SEND A MESSAGE
            Message* makeError( string errorMessage , unsigned int* nonce );     //  GENERATES AN ERROR MESSAGE

        public:
            MainServer( string ipAddr , int port );                  //  GENERATES THE SERVER
            void server();                                           //  STARTS THE SERVER

    };

}


#endif //FOURINAROW_MAINSERVER_H

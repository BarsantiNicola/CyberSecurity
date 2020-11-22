
#ifndef FOURINAROW_USERINFORMATION_H
#define FOURINAROW_USERINFORMATION_H

#include <iostream>
#include "../utility/NetMessage.h"
#include "../cipher/CipherDH.h"

using namespace std;

namespace server {

    //  status available for a user each status represent a set of operation available for the user
    enum UserStatus{

        CONNECTED,   //  the client is connected but the user isn't logged. ONLY LOGIN IS AVAILABLE
        LOGGED,      //  the user is logged. USER_LIST_REQ, RANK_LIST_REQ, MATCH, ACCEPT, REJECT, WITHDRAW ARE AVAILABLE
        WAIT_MATCH,  //  the user is logged and waiting a player accept its match request. USER_LIST_REQ, RANK_LIST_REQ, ACCEPT, REJECT WITHDRAW ARE AVAILABLE
        PLAY         //  the user is currently playing a match. MOVE,CHAT,DISCONNECT ARE AVAILABLE

    };

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                      //
    //                                   USER INFORMATION                                   //
    //    The class maintains information about a logged user. It could be used also to     //
    //    retrieve the socket associated with the client from which the user is connected   //
    //    and from it obtain the information related to the client in server:ClientRegister //
    //                                                                                      //
    //////////////////////////////////////////////////////////////////////////////////////////

    class UserInformation{

        private:
            int socket;         //  USED TO LINK THE USER INFORMATION TO THE CLIENT INFORMATION OF A USER
            string username;    //  USED TO RETRIEVE THE INFORMATION OF A USER
            cipher::SessionKey* sessionKey;  // AES-256 GCM SESSION KEY OF THE USER
            UserStatus status;  //  STATUS OF THE USER. USED TO DETERMINE WHICH KIND OF OPERATIONS THE USER IS ABLE TO PERFORM

        public:
            UserInformation( int socket, string username  );
            UserInformation( int socket, string username, UserStatus status,  cipher::SessionKey* key );

            bool setSessionKey( cipher::SessionKey* key );
            bool setStatus( UserStatus status );

            int getSocket();
            string getUsername();
            cipher::SessionKey* getSessionKey();
            UserStatus* getStatus();

    };

}

#endif //FOURINAROW_USERINFORMATION_H

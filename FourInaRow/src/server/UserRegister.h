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

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   USER REGISTER                                   //
    //    The class maintans information about a logged users(socket,username,keys and   //
    //    a status). It permits to easily add or remove a user from the register,        //
    //    verify the presence of a user or set its status. The class has also gives      //
    //    a set of functionality to get information from a registered user and to        //
    //    generate a list of all the available connected users.                          //                                                                        //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class UserRegister {

        private:
            vector <UserInformation> userRegister;

        public:
            bool addUser(int socket, string username);                    //  ADDS A NEW USER TO THE REGISTER
            bool removeUser(string username);                              //  REMOVES A USER IDENTIFIED BY ITS USERNAME
            bool removeUser(int socket);                                   //  REMOVES A USER IDENTIFIED BY ITS SOCKET

            bool setNonce(string username, int nonce);                    //  SETS A NONCE FOR THE USER
            bool setLogged(string username, cipher::SessionKey *key);     //  SETS THE USER TO LOGGED
            bool setPlay(string username);                                 //  SETS THE USER TO PLAY A MATCH
            bool setWait(string username);                                 //  SETS THE USER TO WAIT A MATCH
            bool setDisconnected(string username);                         //  SETS THE USER TO DISCONNECTED
            bool setSessionKey(string username, cipher::SessionKey *key); //  SETS THE AES256 SESSION PARAMETERS FOR THE USER

            bool has(int socket);                                          //  VERIFIES THE PRESENCE OF A USER BY ITS SOCKET
            bool has(string username);                                     //  VERIFIES THE PRESENCE OF A USER BY ITS USERNAME

            cipher::SessionKey *getSessionKey(string username);            //  GIVES THE SESSION KEY OF A USER
            int *getNonce(string username);                        //  GIVES THE NONCE OF A USER
            UserStatus *getStatus(string username);                       //  GIVES THE STATUS OF A USER
            string getUsername(int socket);                          //  GIVES THE USERNAME OF A USER
            NetMessage *getUserList(string username);                     //  GIVES A FORMATTED STRING OF AVAILABLE USERS

    };
}


#endif //FOURINAROW_USERREGISTER_H

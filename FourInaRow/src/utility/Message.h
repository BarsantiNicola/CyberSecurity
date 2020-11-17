

#ifndef FOURINAROW_MESSAGE_H
#define FOURINAROW_MESSAGE_H

#include <string>
#include <openssl/evp.h>
#include <cstring>
#include <iostream>
#include "../Logger.h"
using namespace std;

namespace utility {

    //  types of message that could be sent by the application
    enum MessageType{

        CERTIFICATE_REQ,    //  (0)  Request to obtain the server'certificate and an authenticated init nonce
        CERTIFICATE,        //  (1)  Response to CERTIFICATE_REQ
        LOGIN_REQ,          //  (2)  Request to login into the service
        LOGIN_OK,           //  (3)  Response to LOGIN_REQ, login correctly done
        LOGIN_FAIL,         //  (4)  Response to LOGIN_REQ, login failed
        KEY_EXCHANGE,       //  (5)  Message to generate a shared AES-256 GCM session key
        USER_LIST_REQ,      //  (6)  Request to obtain the logged users ready to accept a challenge
        USER_LIST,          //  (7)  Response to USER_LIST_REQ
        RANK_LIST_REQ,      //  (8)  Request to obtain the ranks of all the users
        RANK_LIST,          //  (0)  Response to RANK_LIST_REQ
        MATCH,              //  (10) Request to challenge a connected user
        ACCEPT,             //  (11) Response to MATCH, the user has accepted the challenge
        REJECT,             //  (12) Response to MATCH, the user has rejected the challenge
        WITHDRAW_REQ,       //  (13) Update for MATCH, the challenge is aborted
        WITHDRAW_OK,        //  (14) Response from WITHDRAW_REQ, the challenged user has removed the pending challenge
        LOGOUT_REQ,         //  (15) Request to logout from the service
        LOGOUT_OK,          //  (16) Response to LOGOUT_REQ, user correctly logged out
        GAME_PARAM,         //  (17) Message to give the game parameters needed by clients to play a match(IP,PORT) and handling the match start
        DISCONNECT,         //  (18) Request/Response for quitting from the match
        ERROR ,             //  (19) Message to inform users about invalid request or errors during the management of a request
        GAME,               //  (20) Message to confirm to the server a match move of a user
        MOVE,               //  (21) Message to send a match move
        CHAT,               //  (22) Message to send a message to the other user during a match
        ACK                 //  (23) Message to confirm the receipt of a message in UDP connection

    };

    ////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                    //
    //                                   MESSAGE                                          //
    //    The class is designed as a container for the information that the application   //
    //    needs to send on the network. It permits easily to access to the fields of a    //
    //    a message or define/change them. It is used by the upper-level functions and    //
    //    can be converter in utility::NetMessage which is the form used by lower-level   //
    //    functions.                                                                      //
    //                                                                                    //
    //    FOR MESSAGE/NETMESSAGE CONVERTION LOOK AT utility::Converter                    //
    //                                                                                    //
    ////////////////////////////////////////////////////////////////////////////////////////

    class Message {

        private:
            MessageType messageType;

            string username = "";
            string adv_username_1 = "";
            string adv_username_2 = "";

            int* nonce = nullptr;
            int* current_token = nullptr;
            int* port = nullptr;

            unsigned char* user_list = nullptr;
            unsigned int user_list_len=0;

            unsigned char* rank_list = nullptr;
            unsigned int rank_list_len = 0;

            unsigned char* server_certificate = nullptr;
            unsigned int certificate_len = 0;

            unsigned char* signature = nullptr;
            unsigned int signature_len = 0;

            unsigned char* signature_2 = nullptr;
            unsigned int signature_2_len = 0;

            unsigned char* pub_Key = nullptr;
            unsigned int pub_key_len = 0;

            unsigned char* net_informations = nullptr;
            unsigned int net_informations_len = 0;

            unsigned char* chosen_column = nullptr;
            unsigned int chosen_column_size = 0;

            unsigned char* message = nullptr;
            unsigned int message_size = 0;

            unsigned char* DH_key = nullptr;
            unsigned int dh_key_len = 0;

        public:

            //  CONSTRUCTORS & DESTRUCTORS
            Message();
            Message(Message&);          //  COPY-CONSTRUCTOR
            ~Message();

            //  SETTERS
            void setMessageType( MessageType type );

            void setUsername( string username );
            void setAdversary_1( string username );
            void setAdversary_2( string username );

            bool setNonce( int nonce );
            bool setCurrent_Token( int current_token );
            bool setPort( int port );

            bool setUserList( unsigned char* user_list, unsigned int len );
            bool setRankList( unsigned char* rank_list, unsigned int len );
            bool setServer_Certificate( unsigned char* certificate , unsigned int len );
            bool setPubKey( unsigned char* key , unsigned int len );
            bool setNetInformations( unsigned char* IP , unsigned int len );
            bool setChosenColumn( unsigned char* chosen_column, unsigned int len );
            bool setMessage( unsigned char* message, unsigned int len );
            bool setSignature( unsigned char* signature , unsigned int len );
            bool setSignatureAES( unsigned char* signature, unsigned int len );
            bool set_DH_key( unsigned char* key , unsigned int len );

            //  GETTERS
            MessageType getMessageType();
            string getUsername();
            string getAdversary_1();
            string getAdversary_2();

            int* getNonce();
            int* getCurrent_Token();
            int* getPort();

            unsigned char* getUserList();
            unsigned int getUserListLen();

            unsigned char* getRankList();
            unsigned int getRankListLen();

            unsigned char* getServerCertificate();
            unsigned int getServerCertificateLength();

            unsigned char* getPubKey();
            unsigned int getPubKeyLength();

            unsigned char* getNetInformations();
            unsigned int getNetInformationsLength();

            unsigned char* getChosenColumn();
            unsigned int getChosenColumnLength();

            unsigned char* getMessage();
            unsigned int getMessageLength();

            unsigned char* getDHkey();
            unsigned int getDHkeyLength();

            unsigned char* getSignature();
            unsigned int getSignatureLen();

            unsigned char* getSignatureAES();
            unsigned int getSignatureAESLen();

            // UTILITIES
            void myCopy( unsigned char* dest, unsigned char* source, int len );  //  UTILITY FUNCTION SIMILAR TO MEMSET


    };



}
#endif //FOURINAROW_MESSAGE_H



#ifndef FOURINAROW_MESSAGE_H
#define FOURINAROW_MESSAGE_H

#include <string>
#include <openssl/evp.h>
#include <cstring>
#include <iostream>
#include "../Logger.h"
using namespace std;

namespace utility {

    //  types of messages that could be sended by the application
    enum MessageType{
        CERTIFICATE_REQ,
        CERTIFICATE,
        LOGIN_REQ,
        LOGIN_OK,
        LOGIN_FAIL,
        KEY_EXCHANGE,
        USER_LIST_REQ,
        USER_LIST,
        RANK_LIST_REQ,
        RANK_LIST,
        MATCH,
        ACCEPT,
        REJECT,
        WITHDRAW_REQ,
        WITHDRAW_OK,
        LOGOUT_REQ,
        LOGOUT_OK,
        GAME_PARAM,
        MOVE,
        CHAT,
        ACK,
        DISCONNECT
    };

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   MESSAGE                                         //
    //    The class is designed as a container for the information that the application  //
    //    needs to send. It permits easily to generate a message and convert it to       //
    //    a form that could be used by the connection_manager(netMessage). Each field    //
    //    must not contain in every form the string "& or it will not be converted       //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class Message {
        private:
            MessageType messageType;

            string username = "";
            string adv_username_1 = "";
            string adv_username_2 = "";
            string user_list = "";
            string rank_list = "";

            int* nonce = nullptr;
            int* current_token = nullptr;

            unsigned char* server_certificate = nullptr;
            unsigned int certificate_len = 0;

            unsigned char* signature = nullptr;
            unsigned int signature_len = 0;

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

            //  COSTRUCTORS AND DESTRUCTORS
            Message();
            Message(Message&);
            ~Message();

            //  SETTERS
            void setMessageType( MessageType type );

            void setUsername( string username );
            void setAdversary_1( string username );
            void setAdversary_2( string username );
            void setUserList( string user_list );
            void setRankList( string rank_list );

            bool setNonce( int nonce );
            bool setCurrent_Token( int current_token );

            bool setServer_Certificate( unsigned char* certificate , unsigned int len );
            bool setPubKey( unsigned char* key , unsigned int len );
            bool setNetInformations( unsigned char* IP , unsigned int len );
            bool setChosenColumn( unsigned char* chosen_column, unsigned int len );
            bool setMessage( unsigned char* message, unsigned int len );
            bool setSignature( unsigned char* signature , unsigned int len );
            bool set_DH_key( unsigned char* key , unsigned int len );

            //  GETTERS

            MessageType getMessageType();
            string getUsername();
            string getAdversary_1();
            string getAdversary_2();
            string getUserList();
            string getRankList();

            int* getNonce();
            int* getCurrent_Token();

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

    };

}
#endif //FOURINAROW_MESSAGE_H

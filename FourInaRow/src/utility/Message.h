

#ifndef FOURINAROW_MESSAGE_H
#define FOURINAROW_MESSAGE_H

#include <string>
#include <openssl/evp.h>

using namespace std;

namespace utility {

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

    class Message {
        private:
            MessageType messageType;
            string username = "";
            string adv_username_1 = "";
            string adv_username_2 = "";
            int* nonce = NULL;
            unsigned char* server_certificate = NULL;
            unsigned char* signature = NULL;
            unsigned char* pub_Key = NULL;
            string net_informations = "";
            int* current_token = NULL;
            int* chosen_column = NULL;
            string message = "";
            unsigned char* DH_key = NULL;
            string user_list = "";
            string rank_list = "";

        public:
            void setUsername( string username );
            void setAdversary_1( string username );
            void setAdversary_2( string username );
            void setNonce( int nonce );
            void setServer_Certificate( unsigned char* certificate );
            void setPubKey( unsigned char* key );
            void setNetInformations( string IP );
            void setCurrent_Token( int current_token );
            void setChosenColumn( int chosen_column );
            void setMessage( string message );
            void set_DH_key( unsigned char* key );
            void setUserList( string user_list );
            void setRankList( string rank_list );
            void setSignature( unsigned char* signature );

            MessageType getMessageType();
            string getUsername();
            string getAdversary_1();
            string getAdversary_2();
            int* getNonce();
            unsigned char*  getServer_Certificate();
            unsigned char* getPubKey();
            string getNetInformations();
            int* getCurrent_Token();
            int* getChosenColumn();
            string getMessage();
            unsigned char* get_DH_key();
            string getUserList();
            string getRankList();
            unsigned char* getSignature();


    };

}
#endif //FOURINAROW_MESSAGE_H



#ifndef FOURINAROW_MESSAGE_H
#define FOURINAROW_MESSAGE_H

#include <string>
#include <openssl/evp.h>

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
            int* nonce = NULL;
            string server_certificate = "";
            string signature = "";
            string pub_Key = "";
            string net_informations = "";
            int* current_token = NULL;
            int* chosen_column = NULL;
            string message = "";
            string DH_key = "";
            string user_list = "";
            string rank_list = "";

        public:
            void setMessageType( MessageType type );
            void setUsername( string username );
            void setAdversary_1( string username );
            void setAdversary_2( string username );
            void setNonce( int nonce );
            void setServer_Certificate( string certificate );
            void setPubKey( string key );
            void setNetInformations( string IP );
            void setCurrent_Token( int current_token );
            void setChosenColumn( int chosen_column );
            void setMessage( string message );
            void set_DH_key( string key );
            void setUserList( string user_list );
            void setRankList( string rank_list );
            void setSignature( string signature );

            ~Message();
            MessageType getMessageType();
            string getUsername();
            string getAdversary_1();
            string getAdversary_2();
            int* getNonce();
            string  getServer_Certificate();
            string getPubKey();
            string getNetInformations();
            int* getCurrent_Token();
            int* getChosenColumn();
            string getMessage();
            string get_DH_key();
            string getUserList();
            string getRankList();
            string getSignature();

    };

}
#endif //FOURINAROW_MESSAGE_H

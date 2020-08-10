
#include "Message.h"

namespace utility {

    Message::~Message(){
    /*    if( nonce != NULL )
            delete nonce;
        if( current_token != NULL )
            delete current_token;
        if( chosen_column != NULL )
            delete chosen_column;*/
    }
    void Message::setMessageType( MessageType t ){
        this->messageType = t;
    }

    void Message::setUsername(string username ){
        this->username = username;
    }

    void Message::setAdversary_1(string username ){
        this->adv_username_1 = username;
    }

    void Message::setAdversary_2(string username ){
        this->adv_username_2 = username;
    }

    void Message::setNonce(int nonce ){
        if( this->nonce == NULL )
            this->nonce = new int();
        *(this->nonce) = nonce;
    }

    void Message::setServer_Certificate( string certificate ){
        this->server_certificate = certificate;
    }

    void Message::setPubKey( string key ){
        this->pub_Key = key;
    }

    void Message::setNetInformations(string IP ){
        this->net_informations = IP;
    }

    void Message::setCurrent_Token( int current_token ){
        if( this->current_token == NULL )
            this->current_token = new int();
        *(this->current_token) = current_token;
    }

    void Message::setChosenColumn( int chosen_column ){
        if( this->chosen_column== NULL )
            this->chosen_column = new int();
        *(this->chosen_column) = chosen_column;
    }

    void Message::setMessage( string message ){
        this->message = message;
    }

    void Message::set_DH_key( string key ){
        this->DH_key = key;
    }

    void Message::setUserList(string user_list ){
        this->user_list = user_list;
    }

    void Message::setRankList(string rank_list ){
        this->rank_list = rank_list;
    }

    void Message::setSignature( string signature ){
        this->signature = signature;
    }

    MessageType Message::getMessageType(){
        return this->messageType;
    }
    string Message::getUsername(){
        return this->username;
    }

    string Message::getAdversary_1(){
        return this->adv_username_1;
    }

    string Message::getAdversary_2(){
        return this->adv_username_2;
    }

    int* Message::getNonce(){
        return this->nonce;
    }

    string  Message::getServer_Certificate(){
        return this->server_certificate;
    }

    string Message::getPubKey(){
        return this->pub_Key;
    }

    string Message::getNetInformations(){
        return this->net_informations;
    }

    int* Message::getCurrent_Token(){
        return this->current_token;
    }

    int* Message::getChosenColumn(){
        return this->chosen_column;

    }

    string Message::getMessage(){
        return this->message;
    }

    string Message::get_DH_key(){
        return this->DH_key;
    }

    string Message::getUserList(){
        return this->user_list;
    }

    string Message::getRankList(){
        return this->rank_list;
    }

    string Message::getSignature(){
        return this->signature;
    }

}
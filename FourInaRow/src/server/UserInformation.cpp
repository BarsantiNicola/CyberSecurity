
#include "UserInformation.h"

namespace server{

    UserInformation::UserInformation( string username , string ip ){

        this->username = username;
        this->status = CONNECTED;
        this->ip = ip;

    }

    UserInformation::UserInformation( string username, UserStatus status , string ip, cipher::SessionKey key ){

        this->username = username;
        this->status = status;
        this->sessionKey = key;
        this->nonce = nullptr;
        this->ip = ip;

    }

    bool UserInformation::setSessionKey( cipher::SessionKey key ){

        this->sessionKey = key;
        return true;

    }

    string UserInformation::getIP() {
        return this->ip;
    }

    cipher::SessionKey UserInformation::getSessionKey(){

        return this->sessionKey;

    }

    void UserInformation::setStatus( UserStatus status ){
        this->status = status;
    }

    UserStatus UserInformation::getStatus(){
        return this->status;
    }
    string UserInformation::getUsername(){
        return this->username;
    }

    void UserInformation::setNonce( int nonce ) {

        this->nonce = new int(nonce);
    }

    int* UserInformation::getNonce() {

        if( this->nonce )
            return new int(*(this->nonce));
        return nullptr;

    }

}

#include "UserInformation.h"

namespace server{

    UserInformation::UserInformation( string username ){

        this->username = username;
        this->sessionKey = nullptr;
        this->len = 0;
        this->status = CONNECTED;

    }

    UserInformation::~UserInformation(){

        if( this->sessionKey ){
            delete[] this->sessionKey;
        }

    }

    bool UserInformation::setSessionKey( unsigned char* key , int len ){

        if( this->sessionKey )
            return false;

        this->sessionKey = key;
        this->len = len;
        return true;

    }

    utility::NetMessage* UserInformation::getSessionKey(){

        return new utility::NetMessage( this->sessionKey, this->len );

    }

    void UserInformation::setStatus( UserStatus status ){
        this->status = status;
    }

    UserStatus UserInformation::getStatus(){
        return this->status;
    }

}

#include "UserInformation.h"

namespace server{

    UserInformation::UserInformation( string username ){

        this->username = username;
        this->sessionKey = nullptr;
        this->len = 0;
        this->status = CONNECTED;

    }

    UserInformation::UserInformation( string username, UserStatus status , utility::NetMessage* key ){

        this->username = username;
        this->status = status;
        this->sessionKey = nullptr;
        this->len = 0;

        if( key->length() != 0 ){
            unsigned char* app = key->getMessage();
            this->sessionKey = new unsigned char[key->length()];
            this->len = key->length();
            for( int a = 0; a<this->len; a++ )
                this->sessionKey[a] = app[a];
            delete[] app;
        }

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
    string UserInformation::getUsername(){
        return this->username;
    }

}
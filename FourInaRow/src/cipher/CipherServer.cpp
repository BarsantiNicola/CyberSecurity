
#include "CipherServer.h"

namespace cipher{

    CipherServer::CipherServer(){

        this->rsa = new CipherRSA("server", "serverPassword", true );
        this->dh  = new CipherDH();
        this->aes = nullptr;//new CipherAES();
        if( !this->rsa || !this->dh /*|| !this->aes*/ ){

            verbose<<"-->[CipherServer][Costructor] Fatal error, unable to load cipher suites"<<'\n';
            exit(1);

        }

    }

    CipherServer::~CipherServer(){
        delete this->rsa;
        delete this->dh;
       // delete this->aes;
    }
    Message* CipherServer::toSecureForm( Message* message ){

        if( message == nullptr ){

            verbose<<"-->[CipherServer][toSecureForm] Error, null pointer message"<<'\n';
            return nullptr;

        }

        NetMessage* msg;

        switch( message->getMessageType()){

            case CERTIFICATE:

               if( this->rsa->sign(message))
                   return message;
               else
                   return nullptr;

            case LOGIN_OK:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case LOGIN_FAIL:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case KEY_EXCHANGE:
                msg = this->dh->generatePartialKey();
                message->set_DH_key(msg->getMessage(), msg->length());
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case RANK_LIST:

                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case USER_LIST:

                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case MATCH:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case GAME_PARAM:

                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case ACCEPT:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case REJECT:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case WITHDRAW_OK:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case DISCONNECT:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case LOGOUT_OK:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            case ERROR:
                if( this->rsa->sign(message))
                    return message;
                else
                    return nullptr;

            default:
                verbose<<"-->[CipherServer][toSecureForm] Error, messageType not supported:"<<message->getMessageType()<<'\n';
                return new Message(*message);
        }
        return message;

    }
    Message* CipherServer::fromSecureForm( Message* message , string username ){

        if( !message ){

            verbose<<"-->[CipherServer][fromSecureForm] Error, null pointer message"<<'\n';
            return nullptr;

        }
        switch( message->getMessageType()){
            case LOGIN_REQ:
                if( !this->rsa->loadUserKey(username )) return nullptr;
                return this->rsa->serverVerifySignature(*message, message->getUsername())?message:nullptr;
            case KEY_EXCHANGE:
                return this->rsa->serverVerifySignature(*message, username)?message:nullptr;
            case USER_LIST_REQ:

            case RANK_LIST_REQ:

            case MATCH:

            case ACCEPT:

            case REJECT:

            case LOGOUT_REQ:

            case DISCONNECT:

            default:
                verbose<<"-->[CipherServer][fromSecureForm] Error, MessageType not supported:"<<message->getMessageType()<<'\n';
                return new Message(*message);

        }

    }

    NetMessage* CipherServer::getServerCertificate(){

        return this->rsa->getServerCertificate();

    }

    SessionKey* CipherServer::getSessionKey( unsigned char* param , unsigned int paramLen ){

        cout<<"Session key generation___________________________________________________"<<endl;
        return this->dh->generateSessionKey( param , paramLen );

    }

    NetMessage* CipherServer::getPartialKey(){

        return this->dh->generatePartialKey();

    }

}

#include "CipherServer.h"

namespace cipher{

    CipherServer::CipherServer(){

        this->rsa = new CipherRSA("server", "serverPassword", true );
        this->dh  = new CipherDH();
        this->aes = new CipherAES();
        if( !this->rsa || !this->dh || !this->aes ){

            verbose<<"-->[CipherServer][Costructor] Fatal error, unable to load cipher suites"<<'\n';
            exit(1);

        }

    }

    CipherServer::~CipherServer(){
        delete this->rsa;
        delete this->dh;
        delete this->aes;
    }

    bool CipherServer::toSecureForm( Message* message , SessionKey* key ){

        if( message == nullptr ){

            verbose<<"-->[CipherServer][toSecureForm] Error, null pointer message"<<'\n';
            return false;

        }

        Message* app;

        switch( message->getMessageType()){

            case CERTIFICATE:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case LOGIN_OK:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case LOGIN_FAIL:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case KEY_EXCHANGE:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case RANK_LIST:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->encryptMessage(*message);
                if( app == nullptr )
                    return false;

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                message->setRankList( app->getRankList(), app->getRankListLen() );
                delete app;
                break;

            case USER_LIST:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->encryptMessage(*message);
                if( app == nullptr )
                    return false;

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                message->setUserList( app->getUserList(), app->getUserListLen() );
                delete app;

                break;

            case MATCH:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case GAME_PARAM:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case ACCEPT:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case REJECT:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case WITHDRAW_OK:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case DISCONNECT:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case LOGOUT_OK:

                if( !key ) return false;
                this->aes->modifyParam( key );
                app = this->aes->encryptMessage(*message);
                if( app == nullptr ) {
                    return false;
                }
                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case ERROR:

                if( !this->rsa->sign(message))
                    return false;
                break;

            default:
                vverbose<<"--> [CipherServer][toSecureForm] Error, messageType not supported:"<<message->getMessageType()<<'\n';
                return false;
        }

        return true;

    }
    bool CipherServer::fromSecureForm( Message* message , string username , SessionKey* key ){

        if( !message ){

            verbose<<"-->[CipherServer][fromSecureForm] Error, null pointer message"<<'\n';
            return false;

        }

        Message* app;
        switch( message->getMessageType()){

            case LOGIN_REQ:

                if( !this->rsa->loadUserKey(username ))
                    return false;

                return this->rsa->serverVerifySignature(*message, message->getUsername());

            case KEY_EXCHANGE:

                return this->rsa->serverVerifySignature(*message, username);

            case USER_LIST_REQ:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                message->setUserList( app->getUserList(), app->getUserListLen() );
                delete app;
                break;

            case RANK_LIST_REQ:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                message->setUserList( app->getRankList(), app->getRankListLen() );
                delete app;
                break;

            case MATCH:

            case ACCEPT:

            case REJECT:

            case LOGOUT_REQ:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ){

                    return false;
                }
                delete app;
                break;

            case DISCONNECT:

            default:
                vverbose<<"--> [CipherServer][fromSecureForm] Error, MessageType not supported:"<<message->getMessageType()<<'\n';


        }

        return true;

    }

    NetMessage* CipherServer::getServerCertificate(){

        return this->rsa->getServerCertificate();

    }

    SessionKey* CipherServer::getSessionKey( unsigned char* param , unsigned int paramLen ){

        return this->dh->generateSessionKey( param , paramLen );

    }

    NetMessage* CipherServer::getPartialKey(){

        return this->dh->generatePartialKey();

    }

}
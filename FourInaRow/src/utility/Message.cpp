
#include "Message.h"

namespace utility {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                   COSTRUCTORS/DESTRUCTORS                                 //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  costructor to allow to no-arguments class instantiation
    Message::Message(){
        nonce = nullptr;
        current_token = nullptr;

        server_certificate = nullptr;
        certificate_len = 0;

        signature = nullptr;
        signature_len = 0;

        pub_Key = nullptr;
        pub_key_len = 0;

        net_informations = nullptr;
        net_informations_len = 0;

        chosen_column = nullptr;
        chosen_column_size = 0;

        message = nullptr;
        message_size = 0;

        DH_key = nullptr;
        dh_key_len = 0;
    }

    //  costructor to allow to usage of the class as a no-pointer function argument
    Message::Message(Message& msg ){

        this->messageType = msg.messageType;

        if( !msg.username.empty())
            this->setUsername( msg.username );

        if( !msg.adv_username_1.empty())
            this->setAdversary_1( msg.adv_username_1 );

        if( !msg.adv_username_2.empty() )
            this->setAdversary_2( msg.adv_username_2 );

        if( msg.user_list )
            this->setUserList( msg.user_list , msg.user_list_len );

        if( msg.rank_list )
            this->setRankList( msg.rank_list , msg.rank_list_len );

        if( msg.nonce )
            this->setNonce(*( msg.nonce ));

        if( msg.current_token )
            this->setCurrent_Token(*( msg.current_token ));

        if( msg.message )
            this->setMessage( msg.message, msg.message_size );

        if( msg.server_certificate )
            this->setServer_Certificate( msg.server_certificate, msg.certificate_len );

        if( msg.signature )
            this->setSignature( msg.signature , msg.signature_len );

        if( msg.pub_Key )
            this->setPubKey( msg.pub_Key, msg.pub_key_len );

        if( msg.net_informations )
            this->setNetInformations( msg.net_informations, msg.net_informations_len );

        if( msg.chosen_column )
            this->setChosenColumn( msg.chosen_column , msg.chosen_column_size );

        if( msg.DH_key )
            this->set_DH_key( msg.DH_key, msg.dh_key_len );

    }

    Message::~Message(){

        if( ! this->username.empty() )
            this->username.clear();

        if( ! this->adv_username_1.empty() )
            this->adv_username_1.clear();

        if( ! this->adv_username_2.empty() )
            this->adv_username_2.clear();

        if( this->nonce )
            delete this->nonce;

        if( this->current_token )
            delete this->current_token;

        if( this->user_list )
            delete[] this->user_list;

        if( this->rank_list )
            delete[] this->rank_list;

        if( this->server_certificate )
            delete[] this->server_certificate;

        if( this->signature )
            delete[] this->signature;

        if( this->pub_Key )
            delete[] this->pub_Key;

        if( this->net_informations )
            delete[] this->net_informations;

        if( this->chosen_column )
            delete[] this->chosen_column;

        if( this->message )
            delete[] this->message;

        if( this->DH_key )
            delete[] this->DH_key;

    }


    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                            SETTERS                                        //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


    void Message::setMessageType( MessageType t ){

        this->messageType = t;
        vverbose<<"--> [Message][setMessageType] Set of MessageType Completed"<<'\n';

    }

    void Message::setUsername( string username ){

        this->username = username;
        vverbose<<"--> [Message][setUsername] Set of Username Completed"<<'\n';

    }

    void Message::setAdversary_1(string username ){

        this->adv_username_1 = username;
        vverbose<<"--> [Message][setAdversary_1] Set of Adversary_1 Completed"<<'\n';

    }

    void Message::setAdversary_2(string username ){

        this->adv_username_2 = username;
        vverbose<<"--> [Message][setAdversary_2] Set of Adversary_2 Completed"<<'\n';

    }

    bool Message::setNonce( int nonce ){

        if( this->nonce == nullptr )
            this->nonce = new int();

        if( this->nonce ) {

            vverbose<<"--> [Message][setNonce] Set of Nonce Completed"<<'\n';
            *(this->nonce) = nonce;
            return true;

        }else {

            verbose << "--> [Message][setNonce] Error during allocation of memory. Operation Aborted" << '\n';
            return false;

        }

    }

    bool Message::setCurrent_Token( int current_token ){

        if( this->current_token == nullptr )
            this->current_token = new int();

        if( this->current_token ){

            vverbose<<"--> [Message][setCurrentToken] Set of CurrentToken Completed"<<'\n';
            *(this->current_token) = current_token;
            return true;

        }else {

            verbose << "--> [Message][setCurrentToken] Error during allocation of memory. Operation Aborted" << '\n';
            return false;

        }

    }

    bool Message::setUserList( unsigned char* user_list , unsigned int len ){

        if( !user_list || len == 0 ){

            verbose<<"--> [Message][setUserList] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->user_list )
            delete[] this->user_list;

        this->user_list = nullptr;
        this->user_list_len = len;

        this->user_list = new unsigned char[ user_list_len ];
        if( this->user_list ) {

            vverbose<<"--> [Message][setUserList] Set of User List Completed"<<'\n';
            myCopy( this->user_list,  user_list, user_list_len );
            return true;

        }else{

            verbose << "--> [Message][setUserList] Error during allocation of memory. Operation Aborted" << '\n';
            this->user_list_len = 0;
            return false;

        }

    }

    bool Message::setRankList(unsigned char* rank_list, unsigned int len ){

        if( !rank_list || len == 0 ){

            verbose<<"--> [Message][setRankList] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->rank_list )
            delete[] this->rank_list;

        this->rank_list = nullptr;
        this->rank_list_len = len;

        this->rank_list = new unsigned char[ rank_list_len ];
        if( this->rank_list ) {

            vverbose<<"--> [Message][setRankList] Set of Rank List Completed"<<'\n';
            myCopy( this->rank_list,  rank_list, rank_list_len );
            return true;

        }else{

            verbose << "--> [Message][setRankList] Error during allocation of memory. Operation Aborted" << '\n';
            this->rank_list = 0;
            return false;

        }
    }

    bool Message::setServer_Certificate( unsigned char* certificate , unsigned int len ){

        if( !certificate || len == 0 ){

            verbose<<"--> [Message][setServerCertificate] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->server_certificate )
            delete[] this->server_certificate;

        this->server_certificate = nullptr;
        this->certificate_len = len;

        this->server_certificate = new unsigned char[ certificate_len ];
        if( this->server_certificate ) {

            vverbose<<"--> [Message][setServerCertificate] Set of Server Certificate Completed"<<'\n';
            myCopy( this->server_certificate,  certificate, certificate_len );
            return true;

        }else{

            verbose << "--> [Message][setServerCertificate] Error during allocation of memory. Operation Aborted" << '\n';
            this->certificate_len = 0;
            return false;

        }
    }



    bool Message::setSignature( unsigned char* signature , unsigned int len ){

        if( !signature || len == 0 ){

            verbose<<"--> [Message][setSignature] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->signature )
            delete[] this->signature;

        this->signature = nullptr;
        this->signature_len = len;

        this->signature = new unsigned char[ signature_len ];
        if( this->signature ) {

            vverbose<<"--> [Message][setSignature] Set of Signature Completed"<<'\n';
            myCopy( this->signature, signature, signature_len );
            return true;

        }else{

            verbose << "--> [Message][setSignature] Error during allocation of memory. Operation Aborted" << '\n';
            this->signature_len = 0;
            return false;

        }

    }

    bool Message::setPubKey( unsigned char* key , unsigned int len ){

        if( !key || len == 0 ){

            verbose<<"--> [Message][setPubKey] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->pub_Key )
            delete[] this->pub_Key;

        this->pub_Key = nullptr;
        this->pub_key_len = len;

        this->pub_Key = new unsigned char[ pub_key_len ];
        if( this->pub_Key ) {

            vverbose<<"--> [Message][setPubKey] Set of Public Key Completed"<<'\n';
            myCopy( this->pub_Key, key, pub_key_len );
            return true;

        }else{

            verbose << "--> [Message][setPubKey] Error during allocation of memory. Operation Aborted" << '\n';
            this->pub_key_len = 0;
            return false;

        }

    }

    bool Message::setNetInformations( unsigned char* IP , unsigned int len ){

        if( !IP || len == 0 ){

            verbose<<"--> [Message][setNetInformations] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->net_informations )
            delete[] this->net_informations;

        this->net_informations = nullptr;
        this->net_informations_len = len;

        this->net_informations = new unsigned char[ net_informations_len ];
        if( this->net_informations ) {

            vverbose<<"--> [Message][setNetInformations] Set of Network Information Completed"<<'\n';
            myCopy( this->net_informations, IP, net_informations_len );
            return true;

        }else{

            verbose << "--> [Message][setNetInformations] Error during allocation of memory. Operation Aborted" << '\n';
            this->net_informations_len = 0;
            return false;

        }

    }

    bool Message::setChosenColumn( unsigned char* chosen_column , unsigned int len ){

        if( !chosen_column || len == 0 ){

            verbose<<"--> [Message][setChosenColumn] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->chosen_column )
            delete[] this->chosen_column;

        this->chosen_column = nullptr;
        this->chosen_column_size = len;

        this->chosen_column = new unsigned char[ this->chosen_column_size ];
        if( this->chosen_column ) {

            vverbose<<"--> [Message][setChosenColumn] Set of Chosen Column Completed"<<'\n';
            myCopy( this->chosen_column,  chosen_column, this->chosen_column_size );
            return true;

        }else{

            verbose << "--> [Message][setChosenColumn] Error during allocation of memory. Operation Aborted" << '\n';
            this->chosen_column_size = 0;
            return false;

        }

    }

    bool Message::setMessage( unsigned char* message, unsigned int len  ){

        if( !message || len == 0 ){

            verbose<<"--> [Message][setMessage] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->message )
            delete[] this->message;

        this->message = nullptr;
        this->message_size = len;

        this->message = new unsigned char[ this->message_size ];
        if( this->message ) {

            vverbose<<"--> [Message][setMessage] Set of Message Completed"<<'\n';
            myCopy( this->message, message, this->message_size );
            return true;

        }else{

            verbose << "--> [Message][setMessage] Error during allocation of memory. Operation Aborted" << '\n';
            this->message_size = 0;
            return false;

        }

    }

    void Message::myCopy( unsigned char* dest, unsigned char* source, int len ){

        for( int a = 0; a<len;a++ )
            dest[a] = source[a];

    }

    bool Message::set_DH_key( unsigned char* key , unsigned int len ){

        if( !key || len == 0 ){

            verbose<<"--> [Message][setMessage] Error invalid arguments. Operation Aborter"<<'\n';
            return false;

        }

        if( this->DH_key )
            delete[] this->DH_key;

        this->DH_key = nullptr;
        this->dh_key_len = len;

        this->DH_key = new unsigned char[ this->dh_key_len ];
        if( this->DH_key ) {

            vverbose<<"--> [Message][setMessage] Set of Diffie-Hellman Parameter Completed"<<'\n';
            myCopy( this->DH_key, key, this->dh_key_len );
            return true;

        }else{

            verbose << "--> [Message][setMessage] Error during allocation of memory. Operation Aborted" << '\n';
            this->dh_key_len = 0;
            return false;

        }

    }


    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                            GETTERS                                        //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


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

        if( !this->nonce) return nullptr;

        int *ret = new int();
        if( !ret ){

            verbose<<"--> [Message][getNonce] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        *ret = *(this->nonce);

        return ret;

    }

    int* Message::getCurrent_Token(){

        if( !this->current_token ) return nullptr;

        int *ret = new int();
        if( !ret ){

            verbose<<"--> [Message][getCurrentToken] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        *ret = *(this->current_token);

        return ret;

    }

    unsigned char* Message::getUserList(){

        return this->user_list;

    }

    unsigned int Message::getUserListLen() {

        return this->user_list_len;

    }

    unsigned char* Message::getRankList(){

        return this->rank_list;

    }

    unsigned int Message::getRankListLen() {

        return this->rank_list_len;

    }

    unsigned char*  Message::getServerCertificate(){

        if( !this->server_certificate || !this->certificate_len ) return nullptr;

        unsigned char* ret = new unsigned char[certificate_len];
        if( !ret ){

            verbose<<"--> [Message][getServerCertificate] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        myCopy( ret, this->server_certificate, this->certificate_len );

        return ret;

    }

    unsigned int Message::getServerCertificateLength(){

        return this->certificate_len;

    }

    unsigned char* Message::getPubKey(){

        if( !this->pub_Key || !this->pub_key_len ) return nullptr;

        unsigned char* ret = new unsigned char[pub_key_len];
        if( !ret ){

            verbose<<"--> [Message][getPubKey] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        myCopy(  ret,  this->pub_Key, this->pub_key_len );

        return ret;

    }

    unsigned int Message::getPubKeyLength(){

        return this->pub_key_len;

    }

    unsigned char* Message::getNetInformations(){

        if( !this->net_informations || !this->net_informations_len ) return nullptr;

        unsigned char* ret = new unsigned char[net_informations_len];
        if( !ret ){

            verbose<<"--> [Message][getNetInformations] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        myCopy( ret, this->net_informations, this->net_informations_len );

        return ret;

    }

    unsigned int Message::getNetInformationsLength(){

        return this->net_informations_len;

    }

    unsigned char* Message::getChosenColumn(){

        if( !this->chosen_column || !this->chosen_column_size ) return nullptr;

        unsigned char* ret = new unsigned char[chosen_column_size];
        if( !ret ){

            verbose<<"--> [Message][getChosenColumn] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        myCopy(  ret, this->chosen_column, this->chosen_column_size );

        return ret;

    }

    unsigned int Message::getChosenColumnLength(){

        return this->chosen_column_size;

    }

    unsigned char* Message::getMessage(){

        if( !this->message || !this->message_size ) return nullptr;

        unsigned char* ret = new unsigned char[message_size];
        if( !ret ){

            verbose<<"--> [Message][getMessage] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        myCopy( ret, this->message, this->message_size );

        return ret;

    }

    unsigned int Message::getMessageLength(){

        return this->message_size;

    }

    unsigned char* Message::getDHkey(){

        if( !this->DH_key || !this->dh_key_len ) return nullptr;

        unsigned char* ret = new unsigned char[dh_key_len];
        if( !ret ){

            verbose<<"--> [Message][getDHkey] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        myCopy(  ret,  this->DH_key, this->dh_key_len );

        return ret;

    }

    unsigned int Message::getDHkeyLength(){

        return this->dh_key_len;

    }

    unsigned char* Message::getSignature(){

        if( !this->signature || !this->signature_len ) return nullptr;

        unsigned char* ret = new unsigned char[signature_len];
        if( !ret ){

            verbose<<"--> [Message][getSignature] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }
        myCopy( ret, this->signature, this->signature_len );

        return ret;

    }

    unsigned int Message::getSignatureLen(){

        return this->signature_len;

    }

}
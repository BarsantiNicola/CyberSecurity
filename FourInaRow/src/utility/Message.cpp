
#include "Message.h"

namespace utility {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                   COSTRUCTORS/DESTRUCTORS                                 //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    Message::Message(){

        nonce = nullptr;
        current_token = nullptr;
        port = nullptr;

        server_certificate = nullptr;
        certificate_len = 0;

        user_list = nullptr;
        user_list_len = 0;

        rank_list = nullptr;
        rank_list_len = 0;

        signature = nullptr;
        signature_len = 0;

        signature_2 = nullptr;
        signature_2_len = 0;

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

    //  copy-constructor
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

        if( msg.port )
            this->setPort(*( msg.port ));

        if( msg.message )
            this->setMessage( msg.message, msg.message_size );

        if( msg.server_certificate )
            this->setServer_Certificate( msg.server_certificate, msg.certificate_len );

        if( msg.signature )
            this->setSignature( msg.signature , msg.signature_len );

        if( msg.signature_2 )
            this->setSignatureAES( msg.signature_2 , msg.signature_2_len );

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

        if( !this->username.empty() )
            this->username.clear();

        if( !this->adv_username_1.empty() )
            this->adv_username_1.clear();

        if( !this->adv_username_2.empty() )
            this->adv_username_2.clear();

        if( this->nonce )
            delete this->nonce;

        if( this->current_token )
            delete this->current_token;

        if( this->port )
            delete port;

        if( this->user_list )
            delete[] this->user_list;

        if( this->rank_list )
            delete[] this->rank_list;

        if( this->server_certificate )
            delete[] this->server_certificate;

        if( this->signature )
            delete[] this->signature;

        if( this->signature_2 )
            delete[] this->signature_2;

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

    void Message::setAdversary_1( string username ){

        this->adv_username_1 = username;
        vverbose<<"--> [Message][setAdversary_1] Set of Adversary_1 Completed"<<'\n';

    }

    void Message::setAdversary_2(string username ){

        this->adv_username_2 = username;
        vverbose<<"--> [Message][setAdversary_2] Set of Adversary_2 Completed"<<'\n';

    }

    bool Message::setNonce( int nonce ){

        if( !this->nonce ){

            try {

                this->nonce = new int( nonce );

            }catch (bad_alloc e) {

                verbose<< "--> [Message][setNonce] Error during the allocation of memory. Operation aborted" << '\n';
                return false;

            }

        }else
            *( this->nonce ) = nonce;

        vverbose<<"--> [Message][setNonce] Set of nonce completed"<<'\n';
        return true;

    }

    bool Message::setCurrent_Token( int current_token ){

        if( !this->current_token ){

            try {

                this->current_token = new int( current_token );

            }catch( bad_alloc e ){

                verbose<< "--> [Message][setCurrentToken] Error during the allocation of memory. Operation aborted" << '\n';
                return false;

            }

        }else
            *( this->current_token ) = current_token;

        vverbose<<"--> [Message][setCurrentToken] Set of CurrentToken Completed"<<'\n';
        return true;

    }

    bool Message::setPort( int port ){

        if( !this->port ){

            try {

                this->port = new int(port);

            } catch (bad_alloc e) {

                verbose<<"--> [Message][setPort] Error during the allocation of memory. Operation aborted"<<'\n';
                return false;

            }

        }else
            *( this->port ) = port;

        vverbose<<"--> [Message][setPort] Set of Port Completed"<<'\n';
        return true;

    }

    bool Message::setUserList( unsigned char* user_list , unsigned int len ){

        if( !user_list || len < 1 ) {

            verbose<<"--> [Message][setUserList] Invalid parameters. Operation aborted"<<'\n';
            return false;

        }

        if( this->user_list )
            delete[] this->user_list;

        this->user_list_len = len;

        try {

            this->user_list = new unsigned char[user_list_len];
            myCopy( this->user_list,  user_list, user_list_len );
            vverbose<<"--> [Message][setUserList] Set of User List Completed"<<'\n';
            return true;

        }catch( bad_alloc e ){

            verbose<<"--> [Message][setUserList] Error during the allocation of memory. Operation aborted"<<'\n';
            this->user_list_len = 0;
            this->user_list = nullptr;

            return false;

        }

    }

    bool Message::setRankList(unsigned char* rank_list, unsigned int len ){

        if( !rank_list || len < 1 ){

            verbose<<"--> [Message][setRankList] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->rank_list )
            delete[] this->rank_list;

        this->rank_list_len = len;

        try {

            this->rank_list = new unsigned char[rank_list_len];
            myCopy(this->rank_list, rank_list, rank_list_len);
            vverbose << "--> [Message][setRankList] Set of Rank List Completed" << '\n';
            return true;

        }catch( bad_alloc e ){

            verbose<<"--> [Message][setRankList] Error during allocation of memory. Operation Aborted"<<'\n';
            this->rank_list = nullptr;
            this->rank_list_len = 0;
            return false;

        }

    }

    bool Message::setServer_Certificate( unsigned char* certificate , unsigned int len ){

        if( !certificate || len < 1 ){

            verbose<<"--> [Message][setServerCertificate] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->server_certificate )
            delete[] this->server_certificate;

        this->certificate_len = len;

        try {

            this->server_certificate = new unsigned char[certificate_len];
            myCopy(this->server_certificate, certificate, certificate_len);
            vverbose<<"--> [Message][setServerCertificate] Set of Server Certificate Completed"<<'\n';
            return true;

        }catch( bad_alloc e ){

            verbose << "--> [Message][setServerCertificate] Error during allocation of memory. Operation Aborted" << '\n';
            this->certificate_len = 0;
            this->server_certificate = nullptr;
            return false;

        }

    }

    bool Message::setSignature( unsigned char* signature , unsigned int len ){

        if( !signature || len < 1 ){

            verbose<<"--> [Message][setSignature] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->signature )
            delete[] this->signature;

        this->signature_len = len;

        try {

            this->signature = new unsigned char[ this->signature_len ];
            myCopy( this->signature, signature, this->signature_len );
            vverbose << "--> [Message][setSignature] Set of Signature Completed" << '\n';
            return true;

        }catch( bad_alloc e ){

            verbose<<"--> [Message][setSignature] Error during allocation of memory. Operation aborted"<<'\n';
            this->signature_len = 0;
            this->signature = nullptr;
            return false;

        }

    }

    bool Message::setSignatureAES( unsigned char* signature , unsigned int len ){

        if( !signature || len < 0 ){

            verbose<<"--> [Message][setSignatureAES] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->signature_2 )
            delete[] this->signature_2;

        this->signature_2_len = len;

        try {

            this->signature_2 = new unsigned char[ this->signature_2_len ];
            vverbose<<"--> [Message][setSignatureAES] Set of Signature Completed"<<'\n';
            myCopy( this->signature_2, signature, signature_2_len );
            return true;

        }catch( bad_alloc e ){

            verbose << "--> [Message][setSignatureAES] Error during allocation of memory. Operation aborted" << '\n';
            this->signature_2_len = 0;
            this->signature_2 = nullptr;
            return false;

        }

    }

    bool Message::setPubKey( unsigned char* key , unsigned int len ){

        if( !key || len < 1 ){

            verbose<<"--> [Message][setPubKey] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->pub_Key )
            delete[] this->pub_Key;

        this->pub_key_len = len;

        try {

            this->pub_Key = new unsigned char[ pub_key_len ];
            myCopy( this->pub_Key, key, pub_key_len );
            vverbose << "--> [Message][setPubKey] Set of Public Key Completed" << '\n';
            return true;

        }catch( bad_alloc e ){

            verbose << "--> [Message][setPubKey] Error during allocation of memory. Operation aborted" << '\n';
            this->pub_Key = nullptr;
            this->pub_key_len = 0;
            return false;

        }

    }

    bool Message::setNetInformations( unsigned char* IP , unsigned int len ){

        if( !IP || len < 1 ){

            verbose<<"--> [Message][setNetInformation] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->net_informations )
            delete[] this->net_informations;

        this->net_informations_len = len;

        try {

            this->net_informations = new unsigned char[ net_informations_len ];
            myCopy(this->net_informations, IP, net_informations_len);
            vverbose<<"--> [Message][setNetInformation] Set of Network Information Completed"<<'\n';
            return true;

        }catch( bad_alloc e ){

            verbose<<"--> [Message][setNetInformation] Error during allocation of memory. Operation aborted"<<'\n';
            this->net_informations_len = 0;
            this->net_informations = nullptr;
            return false;

        }

    }

    bool Message::setChosenColumn( unsigned char* chosen_column , unsigned int len ){

        if( !chosen_column || len < 1 ){

            verbose<<"--> [Message][setChosenColumn] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->chosen_column )
            delete[] this->chosen_column;

        this->chosen_column_size = len;

        try {

            this->chosen_column = new unsigned char[this->chosen_column_size];
            myCopy(this->chosen_column, chosen_column, this->chosen_column_size);
            vverbose << "--> [Message][setChosenColumn] Set of Chosen Column Completed" << '\n';
            return true;

        }catch( bad_alloc e ){

            verbose << "--> [Message][setChosenColumn] Error during allocation of memory. Operation aborted" << '\n';
            this->chosen_column_size = 0;
            this->chosen_column = nullptr;
            return false;

        }

    }

    bool Message::setMessage( unsigned char* message, unsigned int len  ){

        if( !message || len < 1 ){

            verbose<<"--> [Message][setMessage] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        if( this->message )
            delete[] this->message;

        this->message_size = len;

        try {

            this->message = new unsigned char[this->message_size];
            myCopy(this->message, message, this->message_size);
            vverbose << "--> [Message][setMessage] Set of Message Completed" << '\n';
            return true;

        }catch( bad_alloc e ){

            verbose << "--> [Message][setMessage] Error during allocation of memory. Operation Aborted" << '\n';
            this->message_size = 0;
            this->message = nullptr;
            return false;

        }

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


    MessageType Message::getMessageType(){ return this->messageType; }

    string Message::getUsername(){ return this->username; }

    string Message::getAdversary_1(){ return this->adv_username_1; }

    string Message::getAdversary_2(){ return this->adv_username_2; }

    int* Message::getNonce(){

        if( !this->nonce ) return nullptr;

        try{

            return new int( *(this->nonce));

        }catch( bad_alloc e ){

            verbose<<"--> [Message][getNonce] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }

    }

    int* Message::getCurrent_Token(){

        if( !this->current_token ) return nullptr;

        try {

            return new int( *(this->current_token));

        }catch( bad_alloc e ){

            verbose<<"--> [Message][getCurrentToken] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }

    }

    int* Message::getPort(){

        if( !this->port ) return nullptr;

        try{

            return new int( *(this->port));

        }catch( bad_alloc e ){

            verbose<<"--> [Message][getPort] Error during allocation of memory. Operation Aborted"<<'\n';
            return nullptr;

        }

    }

    unsigned char* Message::getUserList(){

        if( !this->user_list || this->user_list_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->user_list_len ];
            myCopy( ret, this->user_list, this->user_list_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getUserListLen() {

        if( this->user_list_len < 0 ) return 0;

        return this->user_list_len;

    }

    unsigned char* Message::getRankList(){

        if( !this->rank_list || this->rank_list_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->rank_list_len ];
            myCopy( ret, this->rank_list, this->rank_list_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getRankListLen() {

        if( this->rank_list_len < 0 ) return 0;

        return this->rank_list_len;

    }

    unsigned char*  Message::getServerCertificate(){

        if( !this->server_certificate || this->certificate_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->certificate_len ];
            myCopy( ret, this->server_certificate, this->certificate_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getServerCertificateLength(){

        if( this->certificate_len < 0 ) return 0;

        return this->certificate_len;

    }

    unsigned char* Message::getPubKey(){

        if( !this->pub_Key || this->pub_key_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->pub_key_len ];
            myCopy( ret, this->pub_Key, this->pub_key_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getPubKeyLength(){

        if( this->pub_key_len < 0 ) return 0;

        return this->pub_key_len;

    }

    unsigned char* Message::getNetInformations(){

        if( !this->net_informations || this->net_informations_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->net_informations_len ];
            myCopy( ret, this->net_informations, this->net_informations_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getNetInformationsLength(){

        if( this->net_informations_len < 0 ) return 0;

        return this->net_informations_len;

    }

    unsigned char* Message::getChosenColumn(){

        if( !this->chosen_column || this->chosen_column_size < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->chosen_column_size ];
            myCopy( ret, this->chosen_column, this->chosen_column_size );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getChosenColumnLength(){

        if( this->chosen_column_size < 0 ) return 0;

        return this->chosen_column_size;

    }

    unsigned char* Message::getMessage(){

        if( !this->message || this->message_size < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->message_size ];
            myCopy( ret, this->message, this->message_size );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getMessageLength(){

        if( this->message_size < 0 ) return 0;

        return this->message_size;

    }

    unsigned char* Message::getDHkey(){

        if( !this->DH_key || this->dh_key_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->dh_key_len ];
            myCopy( ret, this->DH_key, this->dh_key_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getDHkeyLength(){

        if( this->dh_key_len < 0 ) return 0;

        return this->dh_key_len;

    }

    unsigned char* Message::getSignature(){

        if( !this->signature || this->signature_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->signature_len];
            myCopy( ret, this->signature, this->signature_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getSignatureLen(){

        if( this->signature_len < 0 ) return 0;

        return this->signature_len;

    }

    unsigned char* Message::getSignatureAES(){

        if( !this->signature_2 || this->signature_2_len < 1 ) return nullptr;

        try{

            unsigned char* ret = new unsigned char[ this->signature_2_len];
            myCopy( ret, this->signature_2, this->signature_2_len );
            return ret;

        }catch( bad_alloc e ){

            return nullptr;

        }

    }

    unsigned int Message::getSignatureAESLen(){

        if( this->signature_2_len < 0 ) return 0;

        return this->signature_2_len;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                    UTILITY FUNCTIONS                                      //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    void Message::myCopy( unsigned char* dest, unsigned char* source, int len ){

        if( len < 0 || !dest || !source ){

            verbose<<"--> [Message][myCopy] Error invalid arguments. Operation aborted"<<'\n';
            return;

        }

        for( int a = 0; a<len;a++ )
            dest[a] = source[a];

    }

}
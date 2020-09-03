
#include "MainServer.h"


namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    MainServer::MainServer( string ipAddr , int port ){

        this->manager = new utility::ConnectionManager( true , ipAddr.c_str(), port );

    }

    //  starts the server. The function doesn't return. It will continue until a fatal error happens or the user manually close
    //  the program by Control-C
    void MainServer::server() {

        Message *message;
        Message *response;
        int socket;
        string ipAddr;
        vector<int> waitSockets;

        if( !this->manager ){
            verbose<<"--> [MainServer][server] Fatal error, unable to find connectionManager"<<'\n';
            return;
        }

        while( true ){

            socket = -1;
            ipAddr.clear();
            waitSockets.clear();

            vverbose<<"--> [MainServer][server] Server waiting to receive a message"<<'\n';
            waitSockets = this->manager->waitForMessage( &socket, &ipAddr );


            if( socket != -1 && !ipAddr.empty() ){

                vverbose<<"--> [MainServer][server] New client connection received: "<<socket<<'\n';
                this->clientRegister.addClient( ipAddr, socket );
                continue;

            }

            if( !waitSockets.size() ){
                verbose<<"--> [MainServer][server] Error into connection management"<<'\n';
                continue;

            }

            for( int sock : waitSockets ){

                if( sock == -1 ) continue;

                try {

                    message = this->manager->getMessage( sock );

                }catch( runtime_error ){

                    vverbose<<"--> [MainServer][server] Client "<<sock<<" disconnected"<<'\n';
                    this->logoutClient( sock );
                    continue;

                }

                if( message ) {

                    vverbose << "--> [MainServer][server] New message(" << message->getMessageType()<< ") received from client: " << sock << '\n';

                    response = this->manageMessage( message, sock );
                    delete message;

                    bool socketClosed = false;

                    if (response) {

                        if (!this->manager->sendMessage(*response, sock, &socketClosed, nullptr, 0) && socketClosed) {

                            vverbose << "--> [MainServer][server] Error, unable to send message, client " << socket << " disconnected" << '\n';

                            vector<int> matches = this->matchRegister.getMatchIds( this->userRegister.getUsername(sock));
                            for( int matchID: matches )
                                this->closeMatch( matchID );

                            this->userRegister.removeUser(socket);
                            this->clientRegister.removeClient(socket);
                        }
                    }

                    delete response;

                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      MESSAGE HANDLERS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  the function verify the message consistency then it will pass it to the correct handler
    Message* MainServer::manageMessage( Message* message, int socket ){

        //  verify the user is not already registered
        if ( !this->clientRegister.has(socket) ) {

            verbose << "--> [MainServer][manageMessage] Error, unregistered socket tried to contact the server" << '\n';
            return this->sendError(string( "UNREGISTERED_SOCK" ), message->getNonce());

        }

        if (!this->userRegister.has(socket) && message->getMessageType() != LOGIN_REQ && message->getMessageType() != CERTIFICATE_REQ ) {

            vverbose << "--> [MainServer][manageMessage] Warning, user not already logged. Invalid request" << '\n';
            return this->sendError(string( "INVALID_REQUEST"), message->getNonce());

        }

        string username = this->userRegister.getUsername(socket);
        if (username.empty() && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ ) {

            vverbose << "--> [MainServer][manageMessage] Error, username not found" << '\n';
            return this->sendError(string( "USER_NOT_FOUND" ), message->getNonce());

        }

        Message* response;
        if( message->getMessageType() != CERTIFICATE_REQ ) {
            //  verification of message consistency

            int *nonce = message->getNonce();
            if (!nonce) {
                verbose << "--> [MainServer][certificateHandler] Error, invalid message. Missing Nonce" << '\n';
                return this->sendError(string("MISSING_NONCE"), nonce);
            }
            int* userNonce = this->clientRegister.getClientNonce( socket );
            if ( !userNonce ){

                verbose << "--> [MainServer][keyExchangeHandler] Error, user nonce not present" << '\n';
                response = this->sendError(string("SERVER_ERROR"), nonce );

                delete nonce;
                return response;

            }

            if( *nonce != *userNonce ){

                verbose<<"--> [MainServer][keyExchangeHandler] Error invalid nonce"<<'\n';
                response = this->sendError(string( "SECURITY_ERROR" ), nonce );

                delete nonce;
                delete userNonce;
                return response;

            }

            delete userNonce;
            delete nonce;
        }

        response = this->userManager( message, username, socket );
        this->clientRegister.updateClientNonce( socket );
        return response;

    }

    //  the function manages the messages which involve only him and the contacted server(no other clients have to be contacted)
    //  if the function has not the authority to manage the message it passes it to the matchManager to manage it
    Message* MainServer::userManager(Message* message, string username , int socket ) {

        Message* ret;
        switch( message->getMessageType() ){

            case utility::CERTIFICATE_REQ:
                ret = this->certificateHandler(message, socket );
                break;
            case utility::LOGIN_REQ:
                ret = this->loginHandler(message, socket );
                break;
            case utility::KEY_EXCHANGE:
                ret = this->keyExchangeHandler(message, username );
                break;
            case utility::USER_LIST_REQ:
                ret = this->userListHandler(message, username );
                break;
            case utility::RANK_LIST_REQ:
                ret = this->rankListHandler(message, username );
                break;
            case utility::LOGOUT_REQ:
                ret = this->logoutHandler(message, username, socket );
                break;
            default:
                ret = this->matchManager( message , username );
        }

        return ret;

    }

    Message* MainServer::matchManager(Message* message, string username ){

        Message* ret;
        cout<<"ok i'm in"<<endl;
        switch( message->getMessageType() ){

            case utility::MATCH:
                ret = this->matchHandler( message, username );
                break;
            case utility::ACCEPT:
                ret = this->acceptHandler( message, username );
                break;
            case utility::REJECT:
                ret = this->rejectHandler( message, username );
                break;
            case utility::WITHDRAW_REQ:
                ret = this->withdrawHandler( message, username );
                break;
            case utility::DISCONNECT:
                ret = this->disconnectHandler( message, username );
                break;

        }

        return ret;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                        EVENT HANDLERS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    void MainServer::logoutClient( int socket ) {
        //  remove from match
        this->userRegister.removeUser( socket );
        this->clientRegister.removeClient( socket );

    }

    bool MainServer::closeMatch( int matchID ){
        /*
        Message *response;
        response->setNonce(this->matchRegister.getMatch(matchID)->getNonce());
        this->matchRegister.removeMatch(matchID);
        return this->cipherServer.toSecureForm(utility::REJECT, response );*/
        return true;

    }

    Message* MainServer::sendError( string errorMessage, int* nonce ){

        vverbose<<"--> [MainServer][sendError] Generation of error message: "<<errorMessage<<'\n';

        Message* response = new Message();
        response->setMessageType( ERROR );
        if( !nonce )
            response->setNonce(generateRandomNonce());
        else
            response->setNonce(*nonce);
        response->setMessage( (unsigned char*)errorMessage.c_str() , errorMessage.length() );

        this->cipherServer.toSecureForm( response , nullptr );
        return response;

    }

    int MainServer::generateRandomNonce(){

        unsigned int seed;
        FILE* randFile = fopen( "/dev/urandom","rb" );
        struct timespec ts;

        if( !randFile ){
            verbose<<" [MainServer][generateRandomNonce] Error, unable to locate urandom file"<<'\n';
            if( timespec_get( &ts, TIME_UTC )==0 ) {
                verbose << "--> [MainServer][generateRandomNonce] Error, unable to use timespec" << '\n';
                srand( time( nullptr ));
            }else
                srand( ts.tv_nsec^ts.tv_sec );
            return rand();
        }

        if( fread( &seed, 1, sizeof( seed ),randFile ) != sizeof( seed )){
            verbose<<" [MainServer][generateRandomNonce] Error, unable to load enough data to generate seed"<<'\n';
            if( timespec_get( &ts, TIME_UTC ) == 0 ) {
                verbose << "--> [MainServer][generateRandomNonce] Error, unable to use timespec" << '\n';
                srand( time( NULL ));
            }else
                srand( ts.tv_nsec^ts.tv_sec );
        }else
            srand(seed);

        fclose( randFile );
        return rand();

    }

    bool  MainServer::sendMessage( Message* message, int socket ){

        bool socketClosed = false;

        if (!this->manager->sendMessage(*message, socket, &socketClosed, nullptr, 0) && socketClosed) {

            vverbose << "--> [MainServer][server] Error, unable to send message, client " << socket << " disconnected" << '\n';

            vector<int> matches = this->matchRegister.getMatchIds( this->userRegister.getUsername(socket));
            for( int matchID: matches )
                this->closeMatch( matchID );

            this->userRegister.removeUser(socket);
            this->clientRegister.removeClient(socket);
            return false;
        }
        return true;
    }

    bool MainServer::sendAcceptMessage( string challenger, string challenged, int* socket ){

        Message* message = new Message();
        if( !socket ) return false;
        int* nonce = this->userRegister.getNonce(this->userRegister.getUsername(*socket));

        if( !nonce )
            return false;

        message->setMessageType( ACCEPT );
        message->setAdversary_1(challenger);
        message->setAdversary_2(challenged);
        message->setNonce(*nonce);
        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(this->userRegister.getUsername(*socket))))
            return false;

        return this->sendMessage( message, *socket );

    }
    bool MainServer::sendRejectMessage( string challenger, string challenged, int* socket ){

        Message* message = new Message();
        if( !socket ) return false;
        int* nonce = this->userRegister.getNonce(this->userRegister.getUsername(*socket));
        if( !nonce )
            return false;
        message->setMessageType( REJECT );
        message->setAdversary_1(challenger);
        message->setAdversary_2(challenged);
        message->setNonce(*nonce);
        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(this->userRegister.getUsername(*socket))))
            return false;

        return this->sendMessage( message, *socket );

    }

    bool MainServer::sendDisconnectMessage( string username ){

        Message* message = new Message();
        int* socket = this->userRegister.getSocket(username);
        int* nonce = this->userRegister.getNonce(username);
        if( !socket || !nonce )
            return false;

        message->setMessageType( DISCONNECT );
        message->setNonce(*nonce);
        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(username )))
            return false;

        return this->sendMessage( message, *socket );

    }

    bool MainServer::sendGameParam( string username , string source ){

        Message* message = new Message();
        int* socket = this->userRegister.getSocket(username);
        int* nonce = this->userRegister.getNonce(username);
        if( !socket || !nonce )
            return false;
        string param = this->clientRegister.getClientNetInformation( *(this->userRegister.getSocket(source)));
        NetMessage* pubKey = this->cipherServer.getPubKey( source );
        if( !pubKey ) return false;

        message->setMessageType( GAME_PARAM );
        message->setNonce(*nonce);
        message->setNetInformations( (unsigned char*)param.c_str(), param.length());
        message->setPubKey( pubKey->getMessage(), pubKey->length());
        delete nonce;

        delete pubKey;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(username )))
            return false;

        return this->sendMessage( message, *socket );

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PROTOCOL HANDLERS                                    //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


    //  the handler manages the CERTIFICATE_REQ requests by generating a formatted message containing the server certificate
    Message* MainServer::certificateHandler( Message* message , int socket ){

        //  preparation of response message
        NetMessage* param = this->cipherServer.getServerCertificate();
        int* nonce = new int(this->generateRandomNonce());

        if(! param ){
            verbose<<"--> [MainServer][certificateHandler] Error, unable to load server certificate"<<'\n';
            return this->sendError( string("SERVER_ERROR"), nonce );
        }



        this->clientRegister.setNonce( socket, *nonce );

        Message* result = new Message();
        result->setNonce( *nonce );
        result->setMessageType(CERTIFICATE );
        result->setServer_Certificate( param->getMessage(), param->length());
        delete param;

        if( !this->cipherServer.toSecureForm( result , nullptr )){
            verbose << "--> [MainServer][certificateHandler] Error, message didn't pass security verification" << '\n';
            delete result;
            result = this->sendError(string("SECURITY_ERROR"), nonce );
        }else
            vverbose<<"--> [MainServer][certificateHandler] CERTIFICATE message correctly generated"<<'\n';

        delete nonce;

        return result;

    }

    //  the handler manages the LOGIN_REQ requests verifying if the user is already registered and its signature is valid
    Message* MainServer::loginHandler( Message* message , int socket ){

        int* nonce = message->getNonce();

        if( message->getUsername().empty() ){
            verbose<<"--> [MainServer][loginHandler] Error, invalid message. Missing username"<<'\n';
            return this->sendError(string("MISSING_USERNAME"), nonce );
        }

        Message* response = new Message();
        response->setNonce(*nonce);


        if( !this->cipherServer.fromSecureForm( message , message->getUsername(), nullptr )){

            verbose<<"--> [MainServer][loginHandler] Error during security verification"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response , nullptr );

            delete nonce;
            return response;

        }

        vverbose<<"--> [MainServer][loginHandler] Message has passed validation check"<<'\n';

        if( this->userRegister.has( message->getUsername() )){  //  if a user is already logger login has to fail

            verbose<<"--> [MainServer][loginHandler] Error, user already logged"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response , nullptr );

            delete nonce;
            return response;

        }

        if( !this->userRegister.addUser( socket, message->getUsername() )){  // add user to register

            verbose<<"--> [MainServer][loginHandler] Error, during user registration"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response, nullptr );

            delete nonce;
            return response;

        }

        if( !this->userRegister.setNonce(message->getUsername(), *nonce) ){    //  save nonce for key_exchange

            verbose<<"-->[MainServer][loginHandler] Error, during the setting of user nonce"<<'\n';
            this->userRegister.removeUser( socket );
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response, nullptr );

            delete nonce;
            return response;

        }

        response->setMessageType( LOGIN_OK );

        if( !this->cipherServer.toSecureForm( response , nullptr )){
            verbose << "-->[MainServer][loginHandler] Error, invalid message Missing Diffie-Hellman Parameter" << '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }

    //  the handler manages the KEY_EXCHANGE requests. After has verified the user is correctly registered and the used nonce is the
    //  same of the user login, the service sends a diffie-hellman parameter to the client and combining it with
    //  the received param generates the values necessary to create a secure net-channel
    Message* MainServer::keyExchangeHandler( Message* message , string username ){

        int *nonce = message->getNonce();
        Message* response;

        if( !this->cipherServer.fromSecureForm( message, username, nullptr )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, message didn't pass the security checks" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        vverbose << "--> [MainServer][keyExchangeHandler] Request has passed security checks" << '\n';

        NetMessage* param = this->cipherServer.getPartialKey();
        response = new Message();
        response->setMessageType( KEY_EXCHANGE );
        response->setNonce( *nonce );
        response->set_DH_key( param->getMessage(), param->length() );
        delete param;

        this->userRegister.setLogged( username , this->cipherServer.getSessionKey( message->getDHkey() , message->getDHkeyLength()));

        if( !this->cipherServer.toSecureForm( response, nullptr )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, during message generation" << '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }

    //  the handler manages the USER_LIST_REQ requests. After it has verified the message consistency it generates
    //  a message containing a formatted list of all the match-available users connected to the server
    Message* MainServer::userListHandler( Message* message  , string username ) {

        int* nonce = message->getNonce();
        Message* response;

        if( !this->cipherServer.fromSecureForm( message, message->getUsername(), this->userRegister.getSessionKey(username) )){

            verbose<<"--> [MainServer][userListHandler] Error. Verification Failure"<<'\n';
            response = this->sendError( string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        if( *(this->userRegister.getStatus( username )) != LOGGED ){

            verbose << "--> [MainServer][rankListHandler] Error, user not allowed" << '\n';
            response = this->sendError(string("INVALID_REQUEST"), nonce );

            delete nonce;
            return response;

        }

        vverbose << "--> [MainServer][userListHandler] Request has passed security checks" << '\n';

        NetMessage *user_list = this->userRegister.getUserList( username );
        response = new Message();

        response->setMessageType( USER_LIST );
        response->setNonce( *nonce );
        response->setUserList( user_list->getMessage(), user_list->length() );

        delete user_list;

        if( !this->cipherServer.toSecureForm(response, this->userRegister.getSessionKey(username)) ){

            verbose << "--> [MainServer][userListHandler] Error during message generation" << '\n';
            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }

    Message* MainServer::rankListHandler( Message* message  , string username ){

        int* nonce = message->getNonce();
        Message* response;

        if( !this->cipherServer.fromSecureForm( message, message->getUsername(),this->userRegister.getSessionKey(username) )){

            verbose<<"--> [MainServer][rankListHandler] Error. Verification Failure"<<'\n';
            response = this->sendError( string( "VERIFICATION_ERROR" ), nonce );

            delete nonce;
            return response;

        }


        if( *(this->userRegister.getStatus(username)) != LOGGED ){

            verbose << "--> [MainServer][rankListHandler] Error, user not allowed" << '\n';
            response = this->sendError(string( "MISSING USERNAME" ), nonce );

            delete nonce;
            return response;

        }

        response = new Message();
        string rank_list = SQLConnector::getRankList();

        response->setMessageType( RANK_LIST );
        response->setNonce( *nonce );
        response->setRankList( (unsigned char*) rank_list.c_str(), rank_list.length() );

        if( !this->cipherServer.toSecureForm(response, this->userRegister.getSessionKey(username) ) ){

            verbose << "-->[MainServer][rankListHandler] Error. Verification Failure"<< '\n';
            delete response;
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }



    Message* MainServer::logoutHandler( Message* message , string username, int socket ){

        int *nonce = message->getNonce();

        Message* response;

        if( !this->cipherServer.fromSecureForm( message , username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][logoutHandler] Error, Verification failure" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;
        }

        if( *(this->userRegister.getStatus(username)) != LOGGED ){

            verbose << "--> [MainServer][logoutHandler] Error, user not in the correct state" << '\n';
            response = this->sendError(string( "INVALID_REQUEST" ), nonce );

            delete nonce;
            return response;

        }

        response = new Message();
        response->setMessageType(LOGOUT_OK );
        response->setNonce( *nonce );



        vector<int> matches = this->matchRegister.getMatchIds( this->userRegister.getUsername( socket ));
        for( int matchID: matches )
            this->closeMatch( matchID );


        if( !this->cipherServer.toSecureForm( response, this->userRegister.getSessionKey(username) )){

            verbose << "-->[MainServer][logoutHandler] Error. Unable to encrypt message"<< '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        if( !this->userRegister.removeUser(username)){

            verbose << "-->[MainServer][logoutHandler] Error. User not found"<< '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

            delete nonce;
            return response;
        }

        delete nonce;
        return response;

    }

    //  manages the MATCH requests. It verifies the users are in te correct states and have the correct information to start a match
    Message* MainServer::matchHandler( Message* message, string username ){

        int* nonce = message->getNonce();

        Message* response;
        if( !this->cipherServer.fromSecureForm( message , username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][matchListHandler] Error, Verification failure" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;
        }

        if( message->getUsername().empty() ){

            verbose<<"--> [MainServer][matchManager] Error missing user informations"<<'\n';
            return this->sendError( "MISSING USERNAMES", this->userRegister.getNonce( username ));

        }

        int* adv_socket = this->userRegister.getSocket( message->getUsername() );
        int* adv_nonce =  this->userRegister.getNonce( message->getUsername() );

        if( !adv_socket || !adv_nonce ){

            verbose<<"--> [MainServer][matchManager] Error, missing challenged informations"<<'\n';
            return this->sendError( "MISSING CHALLENGER INFO", this->userRegister.getNonce( username ));

        }

        if( !this->userRegister.has( message->getUsername()) ){

            verbose << "--> [MainServer][matchListHandler] Error, user not in the correct state" << '\n';
            response = this->sendError(string( "INVALID_REQUEST" ), nonce );

            delete nonce;
            return response;

        }

        if( this->matchRegister.getMatchID(username) != -1 ){

            verbose<<"--> [MainServer][matchListHandler] Error, user already has registered a match"<<'\n';
            response = this->sendError(string( "INVALID_REQUEST" ), nonce );

            delete nonce;
            return response;

        }

        if( *(this->userRegister.getStatus(message->getUsername()) ) == CONNECTED || *(this->userRegister.getStatus(message->getUsername())) == PLAY ){

            verbose<<"--> [MainServer][matchListHandler] Error, challenged unable to accept match requests"<<'\n';
            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1(username);
            response->setAdversary_2(message->getUsername());
            response->setNonce( *nonce );
            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][matchListHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }

            delete nonce;
            return response;

        }

        cipher::SessionKey* userKey = this->userRegister.getSessionKey( message->getUsername());

        if( !userKey ){

            verbose<<"--> [MainServer][matchListHandler] Error, challenged unable to accept match requests"<<'\n';
            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1(username);
            response->setAdversary_2( message->getUsername());
            response->setNonce( *nonce );
            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][matchListHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }

            delete nonce;
            return response;

        }

        if( !this->matchRegister.addMatch( username, message->getUsername())){

            verbose<<"--> [MainServer][matchListHandler] Error, challenged unable to accept match requests"<<'\n';

            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );
            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchListHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError( string( "SERVER_ERROR" ), nonce );

            }

            delete nonce;
            return response;

        }

        this->userRegister.setWait( username );
        response = new Message();
        response->setMessageType( MATCH );
        response->setUsername( username );
        response->setNonce( *adv_nonce );

        if( !this->cipherServer.toSecureForm( response , userKey )){

            verbose<<"--> [MainServer][matchListHandler] Error, challenged unable to accept match requests"<<'\n';
            this->userRegister.setLogged( username, this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch(this->matchRegister.getMatchID(username));
            delete message;
            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1(username);
            response->setAdversary_2( message->getUsername());
            response->setNonce( *nonce );
            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchListHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }

        }

        if( !this->sendMessage( response , *adv_socket)){

            verbose<<"--> [MainServer][matchListHandler] Error, challenged unable to accept match requests"<<'\n';
            this->userRegister.setLogged( username , this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch(this->matchRegister.getMatchID(username));
            delete message;
            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1(username);
            response->setAdversary_2( message->getUsername());
            response->setNonce( *nonce );
            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchListHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }
            delete userKey;
            delete nonce;
            return response;

        }

        delete userKey;
        delete nonce;
        return nullptr;

    }

    //  manages the ACCEPT requests. It verifies that a match is present and in the correct state
    Message* MainServer::acceptHandler( Message* message , string username ){
        cout<<"A"<<endl;
        int* nonce = message->getNonce();
        Message* response;
        cout<<"A1"<<endl;
        unsigned char* sign = message->getSignature();
        cout<<"USERNAME: "<<username<<endl;
        cout<<"NONCE: "<<*message->getNonce()<<endl;
        cout<<"CHALLENGER: "<<message->getAdversary_1()<<endl;
        cout<<"CHALLENGED: "<<message->getAdversary_2()<<endl;
        cout<<"SIGNATURE: ";
        for( int a = 0; a<message->getSignatureLen(); a++ )
            cout<<(int)sign[a];
        cout<<endl;
        if( !this->cipherServer.fromSecureForm( message , username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }
        cout<<"B"<<endl;
        if( message->getAdversary_1().empty() || message->getAdversary_2().empty()){

            verbose<< "--> [MainServer][acceptHandler] Error, Missing usernames"<<'\n';
            response = this->sendError( "MISSING_USERNAME" , nonce );

        }
        cout<<"C"<<endl;
        int matchID = this->matchRegister.getMatchID( message->getAdversary_1() );

        if( matchID == -1 ){

            response = new Message();
            verbose<<"--> [MainServer][acceptHandler] Error, match doesn't exists"<<'\n';
            response->setMessageType( DISCONNECT );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][acceptHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError( string("SERVER_ERROR") , nonce );

            }

            delete nonce;
            return response;

        }
        cout<<"D"<<endl;
        if( this->sendAcceptMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket( message->getAdversary_1()))){
            cout<<"E"<<endl;
            this->userRegister.setPlay(message->getAdversary_1());
            this->userRegister.setPlay(message->getAdversary_2());
            this->matchRegister.setAccepted( matchID );

        }else {
            cout<<"F"<<endl;
            this->userRegister.setLogged(message->getAdversary_1(), this->userRegister.getSessionKey(message->getAdversary_1()));
            this->userRegister.setLogged(username, this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch(matchID);

            delete response;
            response = new Message();
            verbose<<"--> [MainServer][acceptHandler] Error, during accept resend"<<'\n';
            response->setMessageType( DISCONNECT );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][acceptHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError( string("SERVER_ERROR") , nonce );

            }

            delete nonce;
            return response;

        }

        this->sendGameParam( message->getAdversary_1(), message->getAdversary_2());
        this->sendGameParam( message->getAdversary_2(), message->getAdversary_1());
        return nullptr;

    }

    Message* MainServer::rejectHandler( Message* message , string username ){

        int* nonce = message->getNonce();
        Message* response;
        if( !this->cipherServer.fromSecureForm( message , username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        if( message->getAdversary_1().empty() || message->getAdversary_2().empty()){

            verbose<< "--> [MainServer][acceptHandler] Error, Missing usernames"<<'\n';
            response = this->sendError( "MISSING_USERNAME" , nonce );

        }

        int matchID = this->matchRegister.getMatchID( message->getAdversary_1() );

        if( matchID == -1 ){

            return nullptr;

        }

        if( this->sendRejectMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket( message->getAdversary_1()))){

            this->userRegister.setLogged(message->getAdversary_1(), this->userRegister.getSessionKey(message->getAdversary_1()));
            this->userRegister.setLogged(username, this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch(matchID);
            return nullptr;

        }else {

            this->userRegister.setLogged(message->getAdversary_1(), this->userRegister.getSessionKey(message->getAdversary_1()));
            this->userRegister.setLogged(username, this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch(matchID);

            return nullptr;

        }

    }

    Message* MainServer::withdrawHandler( Message* message , string username ){

        int* nonce = message->getNonce();
        Message* response;
        if( !this->cipherServer.fromSecureForm( message , username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        int matchID = this->matchRegister.getMatchID( username );

        if( matchID == -1 ){

            verbose << "--> [MainServer][withdrawReqHandler] Error, match doesn't exist" << '\n';
            response = this->sendError(string( "MISSING_MATCH" ), nonce );

            delete nonce;
            return response;

        }

        string selUsername = this->matchRegister.getChallenged( matchID );
        response = new Message();
        response->setMessageType( WITHDRAW_REQ );
        response->setUsername( username );
        response->setNonce( *(this->userRegister.getNonce(selUsername)));

        this->matchRegister.removeMatch( matchID );
        this->userRegister.setLogged( username , this->userRegister.getSessionKey(username));

        if( this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( selUsername ))){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

            delete nonce;
            return response;
        }

        this->sendMessage(response, *(this->userRegister.getSocket(selUsername)));

        delete response;
        response = new Message();
        response->setMessageType( WITHDRAW_OK );
        response->setUsername( selUsername );
        response->setNonce( *nonce );
        if( this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }

    Message* MainServer::disconnectHandler( Message* message, string username ){
        return nullptr;
    }

}

int main() {

    Logger::setThreshold( VERBOSE );
    MainServer* server = new MainServer( string("127.0.0.1") , 12345 );
    server->server();
    return 0;


}





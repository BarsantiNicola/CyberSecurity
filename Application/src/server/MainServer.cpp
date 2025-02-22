
#include "MainServer.h"


namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  the constructor binds the server socket for accepting the clients requests
    MainServer::MainServer( string ipAddr , int port ){

        this->manager = new utility::ConnectionManager( true , ipAddr.c_str(), port );
        base << "---> [MainServer][Constructor] Server build completed" << '\n';

    }

    //  starts the server. The function doesn't return. It will continue until a fatal error happens or the user manually close
    //  the program by typing Control-C
    void MainServer::server( string myIPaddr ) {

        Message *message;
        Message *response;
        int socket;
        string ipAddr;
        vector<int> waitSockets;
        base<<"---> [MainServer][server] Starting server.."<<'\n';

        if( !this->manager ){

            verbose<<"--> [MainServer][server] Fatal error, unable to find connectionManager"<<'\n';
            return;

        }

        base<<"---> [MainServer][server] Server ready to receive messages"<<'\n';
        while( true ){

            socket = -1;
            ipAddr.clear();
            waitSockets.clear();

            //  wait for a new message
            waitSockets = this->manager->waitForMessage( &socket, &ipAddr );

            if( socket != -1 && !ipAddr.empty() ){

                base<<"---> [MainServer][server] New client connection received on socket: "<<socket<<'\n';
                if( !ipAddr.compare("127.0.0.1"))
                	this->clientRegister.addClient(myIPaddr, socket);
                else
                	this->clientRegister.addClient( ipAddr, socket );
                continue;

            }

            if( !waitSockets.size() ){

                verbose<<"--> [MainServer][server] Error into connection management. Unable to find sockets"<<'\n';
                continue;

            }

            //  for each socket we verify if there is a pending message
            for( int sock : waitSockets ){

                if( sock == -1 ) continue;

                try {

                    //  the generation of the Message class perform a first sanitization of the tainted data
                    //  if something invalid its found(missing fields, invalid characters into a field) a null message will be given
                    message = this->manager->getMessage( sock );

                }catch( runtime_error e ){

                    base<<"---> [MainServer][server] Client "<<sock<<" disconnected"<<'\n';
                    this->logoutClient( sock );
                    this->clientRegister.removeClient( sock );
                    continue;

                }

                if( message ) {

                    base << "---> [MainServer][server] New message received from client: " << sock << '\n';

                    //  send the message to the management level which will return back a response if needed
                    response = this->manageMessage( message, sock );
                    delete message;

                    bool socketClosed = false;

                    // if there is a response we send it back
                    if ( response ) {

                        if ( !this->manager->sendMessage( *response, sock, &socketClosed, nullptr, 0 ) && socketClosed ){

                            verbose << "--> [MainServer][server] Error, unable to send message, client " << socket << " disconnected" << '\n';

                            this->logoutClient( sock );
                            this->clientRegister.removeClient(sock);

                        }else
                            base << "---> [MainServer][server] Response to client "<<sock<<" sent: "<<response->getMessageType()<<'\n';

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

    //  The function performs a verification of the message nonce validity.
    //  Then eventually decrypts the message fields and finally assign it to a skeleton function to its management
    Message* MainServer::manageMessage( Message* message, int socket ){

        //  verification of function parameters
        if( !message || socket < 0 ){

            verbose<<"--> [MainServer][manageMessage] Error, invalid parameter. Operation aborted"<<'\n';
            return nullptr;

        }

        base<<"----> [MainServer][manageMessage] Starting message content verification"<<'\n';

        if ( !this->clientRegister.has(socket) ) {

            verbose << "--> [MainServer][manageMessage] Error, unregistered socket tried to contact the server" << '\n';
            return this->makeError( string( "Invalid request. Your socket is not registered into the service. Try to restart your application" ), message->getNonce() );

        }

        //  CERTIFICATE_REQ and LOGIN_REQ must fail if the user is already logged into the service
        if ( !this->userRegister.has(socket) && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ ){

            verbose << "--> [MainServer][manageMessage] Warning, user not already logged. Invalid request" << '\n';
            return this->makeError( string( "Invalid request. You have to login to the service before" ), message->getNonce() );

        }

        //  verification of the user registration
        string username = this->userRegister.getUsername(socket);
        if ( username.empty() && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ ) {

            verbose << "--> [MainServer][manageMessage] Error, username not found" << '\n';
            return this->makeError( string( "Invalid request. You have to login to the service before" ), message->getNonce() );

        }

        Message* response;
        //  if the message is a CERTIFICATE_REQ or GAME the nonce verification is not needed for nonce miss(CERTIFICATE_REQ) or
        //  it is performed separately(GAME) for particular management
        if( message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != GAME ) {

            //  NONCE VERIFICATION

            unsigned int *nonce = message->getNonce();
            if ( !nonce ) {

                vverbose << "--> [MainServer][manageMessage] Error, invalid message. Missing Nonce" << '\n';
                return this->makeError( string( "Invalid request. The service requires a nonce" ), nonce );

            }

            unsigned int* userNonce = this->clientRegister.getClientReceiveNonce( socket );
            if ( !userNonce ){

                verbose << "--> [MainServer][manageMessage]] Error, user nonce not present" << '\n';
                response = this->makeError(string( "Server error. The service is unable to find your information" ), nonce );

                delete nonce;
                return response;

            }

            if( *nonce < *userNonce ){

                vverbose<<"--> [MainServer][manageMessage] Error invalid nonce"<<'\n';
                response = this->makeError(string( "Security error. The nonce you give is invalid" ), nonce );

                delete nonce;
                delete userNonce;

                return response;

            }

            if( message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ && message->getMessageType() != KEY_EXCHANGE )
                this->clientRegister.updateClientReceiveNonce( socket, *nonce+1 );

            delete userNonce;
            delete nonce;

        }

        base<<"----> [MainServer][manageMessage] Nonce verification passed. Start message management.."<<'\n';

        response = this->userManager( message, username, socket );

        if( response && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ && message->getMessageType() != KEY_EXCHANGE )
            this->clientRegister.updateClientNonce( socket );

        return response;

    }

    //  the function manages the messages which involve only a single client that contacts the server(no other clients have to be contacted)
    //  if the function hasn't the authority to manage the message it passes it to the matchManager to manage it
    Message* MainServer::userManager(Message* message, string username , int socket ) {

        if( !message || socket<0 ){

            verbose<<"--> [MainServer][userManager] Error, invalid parameters. Operation aborted"<<'\n';
            return nullptr;

        }

        unsigned int* nonce = this->clientRegister.getClientNonce( socket );
        Message* ret;

        switch( message->getMessageType() ){

            case utility::CERTIFICATE_REQ:
                verbose<<"-----> [MainServer][userManager] Message received: CERTIFICATE_REQ"<<'\n';
                ret = this->certificateHandler( message, socket );
                break;

            case utility::LOGIN_REQ:
                verbose<<"-----> [MainServer][userManager] Message received: LOGIN_REQ"<<'\n';
                ret = this->loginHandler( message, socket, nonce );
                break;

            case utility::KEY_EXCHANGE:
                verbose<<"-----> [MainServer][userManager] Message received: KEY_EXCHANGE"<<'\n';
                ret = this->keyExchangeHandler( message, username, nonce );
                break;

            case utility::USER_LIST_REQ:
                verbose<<"-----> [MainServer][userManager] Message received: USER_LIST_REQ"<<'\n';
                ret = this->userListHandler( message, username, nonce );
                break;

            case utility::RANK_LIST_REQ:
                verbose<<"-----> [MainServer][userManager] Message received: RANK_LIST_REQ"<<'\n';
                ret = this->rankListHandler( message, username, nonce );
                break;

            case utility::LOGOUT_REQ:
                verbose<<"-----> [MainServer][userManager] Message received: LOGOUT_REQ"<<'\n';
                ret = this->logoutHandler( message, username, socket, nonce );
                break;

            default:
                ret = this->matchManager( message , username, nonce );
                break;

        }

        if( nonce )
            delete nonce;

        return ret;

    }

    //  the function manages the messages which involve two clients which interact exchanging messages using the server acting as a relay
    Message* MainServer::matchManager(Message* message, string username, unsigned int* nonce ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][matchManager] Error, missing parameters. Operation aborted"<<'\n';
            return nullptr;

        }

        Message* ret;
        switch( message->getMessageType() ){

            case utility::MATCH:
                verbose<<"-----> [MainServer][matchManager] Message received: MATCH"<<'\n';
                ret = this->matchHandler( message, username, nonce );
                break;

            case utility::ACCEPT:
                verbose<<"-----> [MainServer][matchManager] Message received: ACCEPT"<<'\n';
                ret = this->acceptHandler( message, username, nonce );
                break;

            case utility::REJECT:
                verbose<<"-----> [MainServer][matchManager] Message received: REJECT"<<'\n';
                ret = this->rejectHandler( message, username, nonce );
                break;

            case utility::WITHDRAW_REQ:
                verbose<<"-----> [MainServer][matchManager] Message received: WITHDRAW_REQ"<<'\n';
                ret = this->withdrawHandler( message, username, nonce );
                break;

            case utility::DISCONNECT:
                verbose<<"-----> [MainServer][matchManager] Message received: DISCONNECT"<<'\n';
                ret = this->disconnectHandler( message, username, nonce );
                break;

            case utility::GAME:
                verbose<<"-----> [MainServer][matchManager] Message received: GAME"<<'\n';
                ret = this->gameHandler( message, username, nonce );
                break;

            default:
                verbose<<"-----> [MainServer][matchManager] Unknown message type"<<'\n';
                break;

        }

        return ret;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           UTILITIES                                       //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  Function to remove a user from the service. The function removes all the pending matches from the client
    //  and then removes it from the service
    void MainServer::logoutClient( int socket ) {

        if( socket < 0 ){

            verbose<<"--> [MainServer][logoutClient] Error, invalid parameter. Operation aborted"<<'\n';
            return;

        }

        base<<"-----> [MainServer][logoutClient] Performing logout of the client"<<'\n';

        //  searching of all the matches in which the user is involved to close them
        vector<int> matches = this->matchRegister.getMatchIds( this->userRegister.getUsername( socket ));
        string username = this->userRegister.getUsername( socket );

        for( int matchID: matches )
            this->closeMatch( username, matchID );

        //  removing the user information
        this->userRegister.removeUser( socket );

        base<<"-----> [MainServer][logoutClient] Logout of user "<<username<<" completed"<<'\n';

    }

    //  Function to securely close a match and inform the other involved client
    void MainServer::closeMatch( string username, int matchID ){

        if( matchID < 0 || username.empty() ){

            verbose<<"--> [MainServer][closeMatch] Error, invalid parameter. Operation aborted"<<'\n';
            return;

        }

        base<<"------> [MainServer][closeMatch] Closing match: "<<matchID<<'\n';
        string challenged = this->matchRegister.getChallenged(matchID);
        string challenger = this->matchRegister.getChallenger(matchID);

        if( challenged.empty() || challenger.empty() ){

            verbose<<"--> [MainServer][closeMatch] Error, unable to find the users"<<'\n';
            return;

        }

        //  if match is started we have to restore client to the LOGGED status
        if( *(this->matchRegister.getMatchStatus( matchID )) == STARTED ){

            this->userRegister.setLogged( challenged, this->userRegister.getSessionKey( challenged ));
            this->userRegister.setLogged( challenger, this->userRegister.getSessionKey( challenger ));
            if( this->matchRegister.getTotalMoves(matchID)>5 ){

                SQLConnector::incrementUserGame( username, LOOSE );
                if( !username.compare(challenged))
                    SQLConnector::incrementUserGame( challenger , WIN );
                else
                    SQLConnector::incrementUserGame( challenged , WIN );

            }

        }

        //  if the user which disconnect is the challenged and the match isn't started we send to the challenger a reject to close its request
        if( *(this->matchRegister.getMatchStatus( matchID )) == OPENED ) {
            if( !challenged.compare(username) ) {

                base << "------> [MainServer][closeMatch] Restoring behavior: sending reject to " << challenged << '\n';
                this->userRegister.setLogged(challenger, this->userRegister.getSessionKey(challenger));
                this->sendRejectMessage(challenger, challenged, this->userRegister.getSocket(challenger));

            }else{

                base << "------> [MainServer][closeMatch] Restoring behavior: sending withdraw to " << challenger << '\n';
                this->sendWithdrawMessage( challenged, challenger,  this->userRegister.getSocket(challenged));

            }

        }else //  otherwise we send a disconnect to the other client
            if( !challenged.compare(username)) {

                base<<"------> [MainServer][closeMatch] Restoring behavior: sending disconnect to challenger: "<<challenger<<'\n';
                this->sendDisconnectMessage(challenger);

            }else {

                base<<"------> [MainServer][closeMatch] Restoring behavior: sending disconnect to challenged: "<<challenged<<'\n';
                this->sendDisconnectMessage(challenged);

            }

        //  finally we remove the match
        this->matchRegister.removeMatch( matchID );
        base<<"------> [MainServer][closeMatch] Match "<<matchID<<" closed"<<'\n';

    }
   

    //  the function generates a random nonce to be given to the clients the perform their requests.
    unsigned int MainServer::generateRandomNonce(){

	unsigned int nonce;
	RAND_poll();

	RAND_bytes( (unsigned char*)&nonce, sizeof(unsigned int) );
        return nonce;

    }

    //  generates an error message to be sent to the client who has made the request
    Message* MainServer::makeError( string errorMessage, unsigned int* nonce ){

        if( errorMessage.empty() ){

            verbose<<"--> [MainServer][makeError] Error invalid arguments. Abort operation"<<'\n';
            return nullptr;

        }

        base<<"-------> [MainServer][makeError] Generation of error message: "<<errorMessage<<'\n';

        Message* response = nullptr;
        try {

            response = new Message();

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][makeError] Error during memory allocation. Operation aborted"<<'\n';
            return nullptr;

        }

        response->setMessageType( ERROR );

        //  can happen that the server doesn't have a valid nonce(error caused for a missing nonce into messages
        //  and user nonce not present
        if( !nonce )
            response->setNonce(generateRandomNonce());
        else
            response->setNonce(*nonce);
        response->setMessage( (unsigned char*)errorMessage.c_str(), errorMessage.length() );

        //  sign the message with a server rsa signature
        if( !this->cipherServer.toSecureForm( response , nullptr )){

            verbose<<"--> [MainServer][makeError] Error unable to secure the message. Operation aborted"<<'\n';
            return nullptr;

        }

        base<<"-------> [MainServer][makeError] Error message generated"<<'\n';
        return response;

    }

    // sends directly a message to a given client[used when server has to interact with two clients simultaneously]
    bool  MainServer::sendMessage( Message* message, int socket ){

        if( !message || socket < 0 ){

            verbose<<"--> [MainServer][sendMessage] Error invalid arguments. Operation aborted"<<'\n';
            return false;

        }

        bool socketClosed = false;

        if ( !this->manager->sendMessage(*message, socket, &socketClosed, nullptr, 0) && socketClosed ) {

            // if the connection with a client is closed we disconnect the user from the service
            vverbose << "--> [MainServer][sendMessage] Error, unable to send message, client " << socket << " disconnected" << '\n';
            this->logoutClient(socket);
            return false;

        }
        return true;

    }

    // sends directly an ACCEPT message to the challenger client given as parameter
    bool MainServer::sendAcceptMessage( string challenger, string challenged, int* socket ){

        if( challenger.empty() || challenged.empty() || !socket ){

            verbose<<"--> [MainServer][sendAcceptMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        base<<"-------> [MainServer][sendAcceptMessage] Sending an accept message to "<<challenger<<'\n';

        unsigned int* nonce = this->clientRegister.getClientNonce( *socket );
        if( !nonce ){

            verbose<<"--> [MainServer][sendAcceptMessage] Error unable to found user nonce. Operation aborted"<<'\n';
            return false;

        }

        Message* message = nullptr;
        try{

            message = new Message();
            message->setMessageType( ACCEPT );
            message->setAdversary_1( challenger );
            message->setAdversary_2( challenged );
            message->setNonce( *nonce );

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][sendAcceptMessage] Error during memory allocation. Operation aborted"<<'\n';
            return false;

        }
        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(this->userRegister.getUsername(*socket)))){

            verbose<<"--> [MainServer][sendAcceptMessage] Error unable to secure the message. Operation aborted"<<'\n';
            return false;

        }
        this->clientRegister.updateClientNonce( *socket );
        return this->sendMessage( message, *socket );

    }

    // sends directly a REJECT message to the challenger client
    bool MainServer::sendRejectMessage( string challenger, string challenged, int* socket ){

        if( challenger.empty() || challenged.empty() || !socket ){

            verbose<<"--> [MainServer][sendRejectMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        base<<"-------> [MainServer][sendRejectMessage] Sending a reject message to "<<challenger<<'\n';

        unsigned int* nonce = this->clientRegister.getClientNonce( *socket );
        if( !nonce ){

            verbose<<"--> [MainServer][sendRejectMessage] Error unable to found user nonce. Operation aborted"<<'\n';
            return false;

        }

        Message* message = nullptr;
        try{

            message = new Message();
            message->setMessageType( REJECT );
            message->setAdversary_1( challenger );
            message->setAdversary_2( challenged );
            message->setNonce( *nonce );

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][sendRejectMessage] Error during memory allocation. Operation aborted"<<'\n';
            return false;

        }
        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(this->userRegister.getUsername(*socket)))){

            verbose<<"--> [MainServer][sendRejectMessage] Error unable to secure the message. Operation aborted"<<'\n';
            return false;

        }
        this->clientRegister.updateClientNonce( *socket );
        return this->sendMessage( message, *socket );

    }

    // sends directly a WITHDRAW_REQ message to the challenged client
    bool MainServer::sendWithdrawMessage( string username, string challenger, int* socket ){

        if( username.empty() ||  !socket ){

            verbose<<"--> [MainServer][sendWithdrawMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        base<<"-------> [MainServer][sendWithdrawMessage] Sending a withdraw_req message to "<<username<<'\n';

        unsigned int* nonce = this->clientRegister.getClientNonce( *socket );
        if( !nonce ){

            verbose<<"--> [MainServer][sendWithdrawMessage] Error unable to found user nonce. Operation aborted"<<'\n';
            return false;

        }

        Message* message = nullptr;
        try{

            message = new Message();
            message->setMessageType( WITHDRAW_REQ );
            message->setUsername( challenger );
            message->setNonce( *nonce );

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][sendWithdrawMessage] Error during memory allocation. Operation aborted"<<'\n';
            return false;

        }
        delete nonce;

        if( !this->cipherServer.toSecureForm( message, this->userRegister.getSessionKey(username))){

            verbose<<"--> [MainServer][sendWithdrawMessage] Error unable to secure the message. Operation aborted"<<'\n';
            return false;

        }
        this->clientRegister.updateClientNonce(*socket);
        return this->sendMessage( message, *socket );

    }

    // sends directly a DISCONNECT message to a client identified by a username
    bool MainServer::sendDisconnectMessage( string username ){

        if( username.empty() ){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        base<<"-------> [MainServer][sendDisconnectMessage] Sending a disconnect message to "<<username<<'\n';

        int* socket = this->userRegister.getSocket( username );
        if( !socket ){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error unable to find user socket. Abort operation"<<'\n';
            return false;

        }

        unsigned int* nonce = this->clientRegister.getClientNonce( *socket );
        if( !nonce ){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error unable to find user nonce. Abort operation"<<'\n';
            delete socket;

            return false;

        }

        Message* message = nullptr;
        try{

            message = new Message();
            message->setMessageType( DISCONNECT );
            message->setNonce( *nonce );

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error during memory allocation. Operation aborted"<<'\n';
            return false;

        }
        delete nonce;

        if( !this->cipherServer.toSecureForm( message, this->userRegister.getSessionKey( username ))){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error unable to secure the message. Operation aborted"<<'\n';
            delete socket;

            return false;

        }

        bool ret = this->sendMessage( message, *socket );
        this->clientRegister.updateClientNonce( *socket );
        delete socket;
        return ret;

    }

    // sends directly a GAME_PARAM message to a client identified by a username with the user information of a source
    bool MainServer::sendGameParam( string username , string source, unsigned int token ){

        if( username.empty() || source.empty()){

            verbose<<"--> [MainServer][sendGameParam] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        base<<"-------> [MainServer][sendGameParam] Sending a game_param message to "<<username<<'\n';

        int* socket = this->userRegister.getSocket(username);
        if( !socket ){

            verbose<<"--> [MainServer][sendGameParam] Error unable to find user socket. Abort operation"<<'\n';
            return false;

        }

        unsigned int* nonce = this->clientRegister.getClientNonce(*socket);
        if( !nonce ){

            verbose<<"--> [MainServer][sendGameParam] Error unable to find user nonce. Abort operation"<<'\n';
            delete socket;

            return false;

        }

        string param = this->clientRegister.getClientNetInformation( *(this->userRegister.getSocket(source)));
        cout<<"NET INFO: "<<param<<endl;
        NetMessage* pubKey = this->cipherServer.getPubKey( source );

        if( !pubKey || param.empty() ){

            verbose<<"--> [MainServer][sendGameParam] Error unable to find user'information. Abort operation"<<'\n';
            delete socket;
            delete nonce;

            return false;

        }

        Message* message = nullptr;
        try{

            message = new Message();
            message->setMessageType( GAME_PARAM );
            message->setCurrent_Token( token );
            message->setNonce(*nonce);
            message->setNetInformations( (unsigned char*)param.c_str(), param.length());
            message->setPubKey( pubKey->getMessage(), pubKey->length());

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][sendGameParam] Error during memory allocation. Operation aborted"<<'\n';
            return false;

        }
        delete nonce;
        delete pubKey;

        if( !this->cipherServer.toSecureForm( message, this->userRegister.getSessionKey(username ))){

            verbose<<"--> [MainServer][sendGameParam] Error unable to secure the message. Operation aborted"<<'\n';
            delete socket;

            return false;

        }

        bool ret = this->sendMessage( message, *socket );
        this->clientRegister.updateClientNonce(*socket);
        delete socket;
        return ret;

    }


    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PROTOCOL HANDLERS                                    //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


    //  the handler manages the CERTIFICATE_REQ requests by generating a formatted message containing the server certificate
    //  and an authenticated nonce to be used for next client requests
    Message* MainServer::certificateHandler( Message* message , int socket ){

        if( !message || socket < 0 ){

            verbose<<"--> [MainServer][certificateHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }
        Message* result = nullptr;

        //  the client could already have a nonce registered from a previous certificate request and he need just to refresh it
        unsigned int *nonce = (unsigned int*)message->getNonce();
        try {

            this->clientRegister.setClientSendNonce( socket, *nonce );
            delete nonce;
            nonce = new unsigned int( this->generateRandomNonce() );
            this->clientRegister.setClientReceiveNonce( socket, *nonce);
            base<<"------> [MainServer][certificateHandler] Generation of random nonce completed: "<<*nonce<<'\n';

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][certificateHandler] Error during memory allocation. Operation aborted"<<'\n';
            return nullptr;

        }

        //  preparation of response message
        NetMessage* param = this->cipherServer.getServerCertificate();
        if( !param ){

            verbose<<"--> [MainServer][certificateHandler] Error, unable to load server certificate"<<'\n';
            result = this->makeError( string( "Server error. The service in unable to find its security information" ), nonce );
            delete nonce;
            return result;

        }

        if( this->userRegister.has( socket )){

            verbose<<"--> [MainServer][certificateHandler] Error, user already registered"<<'\n';
            delete param;
            result = this->makeError( string( "Invalid request. The user is already logged" ), nonce );
            delete nonce;
            return result;

        }


        try{

            result = new Message();
            result->setNonce( *nonce );
            result->setCurrent_Token( *message->getNonce());
            result->setMessageType(CERTIFICATE );
            result->setServer_Certificate( param->getMessage(), param->length() );

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][certificateHandler] Error during memory allocation. Operation aborted"<<'\n';
            if( result ) delete result;
            result = this->makeError(  string("Internal server error. Try again"), nonce );
            delete nonce;
            delete param;
            return result;

        }

        delete param;

        if( !this->cipherServer.toSecureForm( result , nullptr )){

            verbose << "--> [MainServer][certificateHandler] Error, message didn't pass security verification" << '\n';
            delete result;
            result = this->makeError( string( "Security error. Invalid message'signature" ), nonce );

        }else
            base<<"------> [MainServer][certificateHandler] CERTIFICATE message correctly generated"<<'\n';

        delete nonce;
        return result;

    }

    //  the handler manages the LOGIN_REQ requests verifying if the user is already registered and its signature is valid
    Message* MainServer::loginHandler( Message* message, int socket, unsigned int* nonce ){

        if( !message || socket<0 || !nonce ){

            verbose<<"--> [MainServer][loginHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        if( message->getUsername().empty() ){

            verbose<<"--> [MainServer][loginHandler] Error, invalid message. Missing username"<<'\n';
            return this->makeError( string( "Invalid request. Missing username" ), nonce );

        }

        Message* response = nullptr;

        try{

            response = new Message();
            response->setNonce( *nonce );

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][loginHandler] Error, during memory allocation. Operation aborted"<<'\n';
            return this->makeError( string("Internal server error. Try again"), nonce );

        }
        base<<"------> [MainServer][loginHandler] Starting analysis of login request validity"<<'\n';

        //  verification of signature
        if( !this->cipherServer.fromSecureForm( message, message->getUsername(), nullptr )){

            verbose<<"--> [MainServer][loginHandler] Error during security verification"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            if( !this->cipherServer.toSecureForm( response, nullptr )){

                verbose << "-->[MainServer][loginHandler] Error, server unable to secure the message"<<'\n';
                delete response;
                response = this->makeError( string( "Internal server error. Try again" ), nonce );

            }

            return response;

        }

        base<<"------> [MainServer][loginHandler] Request has passed signature verification"<<'\n';
        //  verification of user not already logged
        if( this->userRegister.has( message->getUsername() )){  //  if a user is already logger login has to fail

            verbose<<"--> [MainServer][loginHandler] Error, user already logged"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            if( !this->cipherServer.toSecureForm( response, nullptr )){

                verbose << "-->[MainServer][loginHandler] Error, server unable to secure the message"<<'\n';
                delete response;
                response = this->makeError( string( "Internal server error. Try again" ), nonce );

            }

            return response;

        }

        if( !this->userRegister.addUser( socket, message->getUsername() )){  // add user to register

            verbose<<"--> [MainServer][loginHandler] Error, during user registration"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            if( !this->cipherServer.toSecureForm( response, nullptr )){

                verbose << "-->[MainServer][loginHandler] Error, server unable to secure the message"<<'\n';
                delete response;
                response = this->makeError( string( "Internal server error. Try again" ), nonce );

            }

            return response;

        }
        base<<"------> [MainServer][loginHandler] User correctly registered into the service"<<'\n';
        //  we had to the ip previously registered(from first connection) the UDP port given with the login message
        this->clientRegister.updateIp( socket, *(message->getPort()));

        response->setMessageType( LOGIN_OK );

        if( !this->cipherServer.toSecureForm( response , nullptr )){
            verbose << "-->[MainServer][loginHandler] Error, server unable to sign the messager" << '\n';
            this->userRegister.removeUser( socket );
            delete response;
            response = this->makeError( string( "Server Error. The service is unable to secure the message" ), nonce );

        }

        base<<"------> [MainServer][certificateHandler] LOGIN_OK message correctly generated"<<'\n';
        return response;

    }

    //  the handler manages the KEY_EXCHANGE requests. After has verified the user is correctly registered and the used nonce is the
    //  same of the user login, the service sends a diffie-hellman parameter to the client and combining it with
    //  the received param generates the values necessary to create a secure net-channel
    Message* MainServer::keyExchangeHandler( Message* message, string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][keyExchangeHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response = nullptr;

        if( !this->userRegister.has( username )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, user not logged" << '\n';
            response = this->makeError( string( "Invalid request. You must login into the service before" ), nonce );

            return response;

        }

        if( *(this->userRegister.getStatus( username )) != CONNECTED ){

            verbose << "--> [MainServer][keyExchangeHandler] Error, key already exchanged" << '\n';
            response = this->makeError( string( "Invalid request. Session key already generated" ), nonce );

            return response;

        }

        if( !this->cipherServer.fromSecureForm( message, username, nullptr )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, message didn't pass the security checks" << '\n';
            response = this->makeError( string( "Security error. Invalid message'signature" ), nonce );

            return response;

        }

        base<<"------> [MainServer][keyExchangeHandler] Request has passed signature verification"<<'\n';
        NetMessage* param = this->cipherServer.getPartialKey();
        if( !param ){

            verbose<<"--> [MainServer][keyExchangeHandler] Error unable to generate diffie-hellman parameter"<<'\n';

            return nullptr;

        }
        base<<"------> [MainServer][keyExchangeHandler] Starting generation of user session key"<<'\n';
        //  nonce presence has already been verified in low level functions
        try {

            response = new Message();
            response->setMessageType( KEY_EXCHANGE );
            response->setNonce( *nonce );
            response->set_DH_key( param->getMessage(), param->length() );

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][keyExchangeHandler] Error during memory allocation. Operation aborted"<<'\n';
            delete param;

            if( response ) delete response;
            this->userRegister.removeUser( username );
            return this->makeError( string( "Server internal error. Try again" ) , nonce );

        }
        delete param;

        this->userRegister.setLogged( username , this->cipherServer.getSessionKey( message->getDHkey() , message->getDHkeyLength() ));

        int* socket = this->userRegister.getSocket( username );
        this->clientRegister.setClientReceiveNonce( *socket, 0 );
        this->clientRegister.setClientSendNonce( *socket, UINT32_MAX/2 );
        delete socket;

        if( !this->cipherServer.toSecureForm( response, nullptr )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, during message generation" << '\n';
            delete response;
            this->userRegister.removeUser( username );
            response = this->makeError(string( "Server error. Service unable to generate message'signature" ), nonce );

        }
        base<<"------> [MainServer][keyExchangeHandler] User "<<username<<" correctly logged into the service"<<'\n';
        base<<"------> [MainServer][certificateHandler] KEY_EXCHANGE message correctly generated"<<'\n';
        return response;

    }

    //  the handler manages the USER_LIST_REQ requests. After it has verified the message consistency it generates
    //  a message containing a formatted list of all the match-available users connected to the server
    Message* MainServer::userListHandler( Message* message  , string username, unsigned int* nonce ) {

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][userListHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response = nullptr;

        if( !this->cipherServer.fromSecureForm( message, message->getUsername(), this->userRegister.getSessionKey( username ))){

            verbose<<"--> [MainServer][userListHandler] Error. Verification Failure"<<'\n';
            response = this->makeError( string( "Security error. Invalid message'signature" ), nonce );

            return response;

        }

        //  if a user is not logged or is playing a match he cannot request a USER_LIST
        if( *(this->userRegister.getStatus( username )) == CONNECTED || *(this->userRegister.getStatus( username )) == PLAY ){

            verbose << "--> [MainServer][userListHandler] Error, user not allowed" << '\n';
            response = this->makeError(string("Invalid request. You aren't in the correct state to make that request" ), nonce );

            return response;

        }

        base<<"------> [MainServer][userListHandler] Request has passed signature verification"<<'\n';
        NetMessage *user_list = this->userRegister.getUserList( username );

        if( !user_list ){

            verbose<<"--> [MainServer][userListHandler] Error unable to obtain the user list"<<'\n';
            return nullptr;

        }
        base<<"------> [MainServer][userListHandler] User list generated"<<'\n';

        try {

            response = new Message();
            response->setMessageType(USER_LIST);
            response->setNonce(*nonce);
            response->setUserList(user_list->getMessage(), user_list->length());

        }catch( bad_alloc e ){

            delete user_list;
            if( response )delete response;
            verbose<<"--> [MainServer][userListHandler] Error during memory allocation. Operation aborted"<<'\n';
            return this->makeError( string("Server Internal Error, Try again"), nonce );

        }
        delete user_list;

        if( !this->cipherServer.toSecureForm(response, this->userRegister.getSessionKey(username)) ){

            verbose << "--> [MainServer][userListHandler] Error during message generation" << '\n';
            delete response;
            response = this->makeError(string( "Server error. Service unable to generate the message'signature" ), nonce );

        }

        base<<"------> [MainServer][userListHandler] USER_LIST message correctly generated"<<'\n';
        return response;

    }

    //  the handler manages the RANK_LIST_REQ requests. After it has verified the message consistency it generates
    //  a message containing a formatted list of all the users game statistics mantained in a remote MySQL server
    Message* MainServer::rankListHandler( Message* message  , string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][rankListHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        //  nonce presence has already been verified in low level functions
        Message* response = nullptr;

        if( !this->cipherServer.fromSecureForm( message, message->getUsername(),this->userRegister.getSessionKey(username) )){

            verbose<<"--> [MainServer][rankListHandler] Error. Verification Failure"<<'\n';
            response = this->makeError( string( "Security error. Invalid message'signature" ), nonce );

            return response;

        }
        base<<"------> [MainServer][rankListHandler] Request has passed signature verification"<<'\n';

        if( *(this->userRegister.getStatus( username )) == CONNECTED || *(this->userRegister.getStatus( username )) == PLAY ){

            verbose << "--> [MainServer][rankListHandler] Error, user not allowed" << '\n';
            response = this->makeError(string( "Invalid request. You aren't in the correct state to make that request" ), nonce );

            return response;

        }


        base<<"------> [MainServer][rankListHandler] Contacting remote SQL database for rank list"<<'\n';
        string rank_list = SQLConnector::getRankList();

        if( rank_list.empty() ){

            verbose<<"--> [MainServer][rankListHandler] Error unable to obtain users statistics"<<'\n';
            return nullptr;

        }

        base<<"------> [MainServer][rankListHandler] Rank list generated"<<'\n';
        try {

            response = new Message();
            response->setMessageType(RANK_LIST);
            response->setNonce(*nonce);
            response->setRankList((unsigned char *) rank_list.c_str(), rank_list.length());

        }catch( bad_alloc e ){

            if( response )delete response;
            verbose<<"--> [MainServer][rankListHandler] Error during memory allocation. Operation aborted"<<'\n';
            return this->makeError( string("Server Internal Error, Try again"), nonce );

        }

        if( !this->cipherServer.toSecureForm(response, this->userRegister.getSessionKey(username) ) ){

            verbose << "-->[MainServer][rankListHandler] Error. Verification Failure"<< '\n';
            delete response;
            response = this->makeError(string( "Server error. The service is unable to generate the message'signature" ), nonce );

        }

        base<<"------> [MainServer][rankListHandler] RANK_LIST message correctly generated"<<'\n';
        return response;

    }

    //  the handler manages LOGOUT_REQ requests. It closes any pending match then it securely delete the user from the service
    Message* MainServer::logoutHandler( Message* message , string username, int socket, unsigned int* nonce ){

        if( !message || username.empty() || socket<0 || !nonce ){

            verbose<<"--> [MainServer][logoutHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response = nullptr;

        if( !this->cipherServer.fromSecureForm( message , username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][logoutHandler] Error, Verification failure" << '\n';
            response = this->makeError( string( "Security error. Invalid message'signature" ), nonce );

            return response;

        }
        base<<"------> [MainServer][logoutHandler] Request has passed signature verification"<<'\n';

        if( *(this->userRegister.getStatus(username)) != LOGGED ){

            verbose << "--> [MainServer][logoutHandler] Error, user not in the correct state" << '\n';
            response = this->makeError(string( "Invalid request. You aren't in the correct state to make that request" ), nonce );

            return response;

        }

        base<<"------> [MainServer][logoutHandler] Starting logout procedure"<<'\n';
        try {

            response = new Message();
            response->setMessageType(LOGOUT_OK);
            response->setNonce(*nonce);

        }catch( bad_alloc e ){

            if( response )delete response;
            verbose<<"--> [MainServer][logoutHandler] Error during memory allocation. Operation aborted"<<'\n';
            return this->makeError( string("Server Internal Error, Try again"), nonce );

        }

        if( !this->cipherServer.toSecureForm( response, this->userRegister.getSessionKey(username) )){

            verbose << "-->[MainServer][logoutHandler] Error. Unable to encrypt message"<< '\n';

            delete response;
            response = this->makeError(string( "Server error. Service unable to generate the message'signature" ), nonce );

        }

        this->logoutClient( socket );
        base<<"------> [MainServer][logoutHandler] User "<<username<<" correctly logged out"<<'\n';
        base<<"------> [MainServer][logoutHandler] LOGOUT_OK message correctly generated"<<'\n';
        return response;

    }

    //  manages the MATCH requests. It verifies the users are in the correct states and have the correct information to start a match
    Message* MainServer::matchHandler( Message* message, string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][matchHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response = nullptr;
        if( !this->cipherServer.fromSecureForm( message, username, this->userRegister.getSessionKey( username ))){

            verbose << "--> [MainServer][matchHandler] Error, Verification failure" << '\n';
            return this->makeError( string( "Security error. Invalid message'signature" ), nonce );

        }

        base<<"------> [MainServer][matchHandler] Request has passed signature verification"<<'\n';

        if( message->getUsername().empty() ){

            verbose<<"--> [MainServer][matchHandler] Error missing user informations"<<'\n';
            return this->makeError( string( "Invalid Request. You have to send a valid username" ), nonce );

        }

        if( !message->getUsername().compare( username )){

            verbose<<"--> [MainServer][matchHandler] Error invalid user information"<<'\n';
            return this->makeError( string( "Invalid Request. You have to send a valid username" ), nonce );

        }

        if( this->matchRegister.getMatchID( username ) != -1 ){

            verbose<<"--> [MainServer][matchHandler] Error, user already has registered a match"<<'\n';
            return this->makeError( string( "Invalid request. You're already registerd a match. Withdraw it before create a new match" ), nonce );

        }

        if( !this->userRegister.has(message->getUsername()) ){

            verbose<<"--> [MainServer][matchHandler] Error, requested user doesn't exits"<<'\n';
            return this->makeError( string( "Invalid request. User doesn't exists" ), nonce );

        }

        try{

            response = new Message();

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][matchHandler] Error during memory allocation. Operation aborted"<<'\n';
            return this->makeError( string( "Internal Server Error. Try again" ), nonce );

        }

        base<<"------> [MainServer][matchHandler] Status verification of challenger user: "<<username<<'\n';
        if( *(this->userRegister.getStatus( username )) != LOGGED ){

            verbose<<"--> [MainServer][matchHandler] Error, challenger unable to accept match requests"<<'\n';
            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = this->makeError(string( "Server error. Service unable to generate the message'signature" ), nonce );

            }

            return response;

        }

        base<<"------> [MainServer][matchHandler] Status verification of challenged user: "<<message->getUsername()<<'\n';

        if( *(this->userRegister.getStatus(message->getUsername()) ) == CONNECTED || *(this->userRegister.getStatus(message->getUsername()) ) == PLAY  ){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';
            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );
            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = this->makeError(string("Server error. Service unable to generate the message'signature"), nonce );

            }

            return response;

        }

        base<<"------> [MainServer][matchHandler] Users verification passed"<<'\n';

        int* adv_socket = this->userRegister.getSocket( message->getUsername() );
        unsigned int* adv_nonce = nullptr;
        if( adv_socket )
            adv_nonce = this->clientRegister.getClientNonce(*adv_socket);

        cipher::SessionKey* userKey = this->userRegister.getSessionKey( message->getUsername());

        if( !adv_socket || !adv_nonce || !userKey ){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';

            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = this->makeError(string("Server error. Service unable to generate the message'signature"), nonce );

            }

            delete userKey;
            delete adv_socket;
            delete adv_nonce;
            return response;

        }

        if( !this->matchRegister.addMatch( username, message->getUsername())){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';

            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = this->makeError( string( "Server error. Service unable to generate the message'signature" ), nonce );

            }

            delete userKey;
            delete adv_socket;
            delete adv_nonce;
            return response;

        }

        base<<"------> [MainServer][matchHandler] New match correctly created"<<'\n';

        this->userRegister.setWait( username );

        response->setMessageType( MATCH );
        response->setUsername( username );
        response->setNonce( *adv_nonce );

        if( !this->cipherServer.toSecureForm( response, userKey )){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';
            this->userRegister.setLogged( username, this->userRegister.getSessionKey( username ));
            this->matchRegister.removeMatch(this->matchRegister.getMatchID( username ));

            delete response;
            try{

                response = new Message();
                response->setMessageType( REJECT );
                response->setAdversary_1( username );
                response->setAdversary_2( message->getUsername() );
                response->setNonce( *nonce );

            }catch( bad_alloc e ){

                verbose<<"--> [MainServer][matchHandler] Error during memory allocation. Operation aborted"<<'\n';
                delete userKey;
                delete adv_socket;
                delete adv_nonce;
                this->userRegister.setLogged( username , this->userRegister.getSessionKey( username ));
                this->matchRegister.removeMatch( this->matchRegister.getMatchID( username ));
                return this->makeError( string( "Internal Server Error. Try again" ), nonce );

            }


            if( !this->cipherServer.toSecureForm( response, this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = this->makeError( string( "Server error. Service unable to generate the message'signature" ), nonce );
                this->userRegister.setLogged( username , this->userRegister.getSessionKey( username ));
                this->matchRegister.removeMatch( this->matchRegister.getMatchID( username ));

            }

            delete userKey;
            delete adv_socket;
            delete adv_nonce;
            return response;

        }

        base<<"------> [MainServer][matchHandler] MATCH message correctly generated"<<'\n';

        if( !this->sendMessage( response , *adv_socket )){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';
            this->userRegister.setLogged( username , this->userRegister.getSessionKey( username ));
            this->matchRegister.removeMatch( this->matchRegister.getMatchID( username ));

            delete response;

            try{

                response = new Message();
                response->setMessageType( REJECT );
                response->setAdversary_1( username );
                response->setAdversary_2( message->getUsername() );
                response->setNonce( *nonce );

            }catch( bad_alloc e ){

                verbose<<"--> [MainServer][matchHandler] Error during memory allocation. Operation aborted"<<'\n';
                delete userKey;
                delete adv_socket;
                delete adv_nonce;
                this->userRegister.setLogged( username , this->userRegister.getSessionKey( username ));
                this->matchRegister.removeMatch( this->matchRegister.getMatchID( username ));
                return this->makeError( string( "Internal Server Error. Try again" ), nonce );

            }


            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = this->makeError(string("Server error. Service unable to generate the message'signature"), nonce );
                this->userRegister.setLogged( username , this->userRegister.getSessionKey( username ));
                this->matchRegister.removeMatch( this->matchRegister.getMatchID( username ));

            }

            delete adv_socket;
            delete adv_nonce;
            delete userKey;
            return response;

        }

        base<<"------> [MainServer][matchHandler] Match correctly sent to: "<<message->getUsername()<<'\n';

        this->clientRegister.updateClientNonce(*adv_socket);
        delete adv_socket;
        delete adv_nonce;
        delete userKey;
        return nullptr;

    }

    //  manages the ACCEPT requests. It verifies that a match is present and in the correct state then if forwards the accept request
    Message* MainServer::acceptHandler( Message* message, string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][acceptHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response = nullptr;

        if( !this->cipherServer.fromSecureForm( message, username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            return this->makeError(string( "Security error. Invalid message'signature" ), nonce );

        }

        base<<"------> [MainServer][acceptHandler] Request has passed signature verification"<<'\n';

        if( message->getAdversary_1().empty() || message->getAdversary_2().empty() ){

            verbose<< "--> [MainServer][acceptHandler] Error, Missing usernames"<<'\n';
            return this->makeError( string( "Invalid request. You have to insert your username and the challenger one" ), nonce );

        }

        if( *(this->userRegister.getStatus( username )) == CONNECTED || *(this->userRegister.getStatus( username )) == PLAY   ){

            verbose<< "--> [MainServer][acceptHandler] Error, user try to accept a challenge before undo previous sent"<<'\n';
            return this->makeError( string( "Invalid request. You aren't in the correct state to accept a match" ), nonce );

        }

        int matchID = this->matchRegister.getMatchID( message->getAdversary_1() );

        if( matchID == -1 ){

            verbose<<"--> [MainServer][acceptHandler] Error, match doesn't exists"<<'\n';

            try {

                response = new Message();
                response->setMessageType( DISCONNECT );
                response->setNonce( *nonce );

            }catch( bad_alloc e ){

                verbose<<"--> [MainServer][acceptHandler] Error during memory allocation. Operation aborted"<<'\n';
                return this->makeError( string( "Server Internal Error. Try again" ), nonce );

            }

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][acceptHandler] Error during security conversion"<<'\n';
                delete response;
                response = makeError( string("Server error. Service unable to generate the message'signature") , nonce );

            }

            return response;

        }

        base<<"------> [MainServer][acceptHandler] Identified membership match: "<<matchID<<'\n';

        if( this->sendAcceptMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket( message->getAdversary_1() ))){

            base<<"------> [MainServer][acceptHandler] ACCEPT message forwarded to: "<<message->getAdversary_1()<<'\n';
            this->userRegister.setPlay( message->getAdversary_1() );
            this->userRegister.setPlay( message->getAdversary_2() );
            this->matchRegister.setAccepted( matchID );

            vector<int> matches = this->matchRegister.getMatchIds( username );
            for( int match: matches )
                if( match != matchID )
                    this->closeMatch( username, match );

        }else {

            verbose<<"--> [MainServer][acceptHandler] Error unable to identify challenger user. Abort"<<'\n';
            int* socket = this->userRegister.getSocket( message->getAdversary_1() );
            if( socket ) {

                this->logoutClient( *socket );
                delete socket;
                return nullptr;

            }else {

                verbose << "--> [MainServer][acceptHandler] Something goes wrong. Server repairing unconsistence" << '\n';
                this->matchRegister.removeMatch( matchID );

            }

            try {

                response = new Message();
                response->setMessageType( DISCONNECT );
                response->setNonce( *nonce );

            }catch( bad_alloc e ){

                verbose<<"--> [MainServer][acceptHandler] Error during memory allocation. Operation aborted"<<'\n';
                return this->makeError( string( "Server Internal Error. Try again" ), nonce );

            }

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][acceptHandler] Error during security conversion"<<'\n';
                this->userRegister.setLogged( message->getAdversary_1(), this->userRegister.getSessionKey( message->getAdversary_1() ));
                this->userRegister.setLogged( message->getAdversary_2(), this->userRegister.getSessionKey( message->getAdversary_2() ));
                this->matchRegister.removeMatch( matchID );
                delete response;
                response = makeError( string( "Server error. Service unable to generate the message'signature. Match aborted" ), nonce );

            }

            return response;

        }

        unsigned int token = generateRandomNonce();
        if( !this->sendGameParam( message->getAdversary_1(), message->getAdversary_2(), token )){

            int* socket = this->userRegister.getSocket( message->getAdversary_1() );
            if( socket ) {

                this->logoutClient( *socket );
                delete socket;
                return nullptr;

            }else{

                verbose << "--> [MainServer][acceptHandler] Something goes wrong. Server repairing unconsistence" << '\n';
                this->matchRegister.removeMatch( matchID );

            }

            this->userRegister.setLogged( username, this->userRegister.getSessionKey( username ));

            try {

                response = new Message();
                response->setMessageType( DISCONNECT );
                response->setNonce( *nonce );

            }catch( bad_alloc e ){

                verbose<<"--> [MainServer][acceptHandler] Error during memory allocation. Operation aborted"<<'\n';
                return nullptr;

            }

            if( !this->cipherServer.toSecureForm( response, this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][acceptHandler] Error during security conversion"<<'\n';
                delete response;
                response = makeError( string( "Server error. Service unable to generate the message'signature" ), nonce );

            }

            return response;

        }

        this->matchRegister.setReady( matchID );

        if( !this->sendGameParam( message->getAdversary_2(), message->getAdversary_1(), token )){

            int* socket = this->userRegister.getSocket( message->getAdversary_2() );
            if( socket ){

                this->logoutClient( *socket );
                delete socket;
                return nullptr;

            }else {

                verbose << "--> [MainServer][acceptHandler] Something goes wrong. Server repair" << '\n';
                this->matchRegister.removeMatch( matchID );

            }

            this->userRegister.setLogged( message->getAdversary_1(), this->userRegister.getSessionKey( message->getAdversary_1() ));

            if(!this->sendRejectMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket( message->getAdversary_1() ))) {

                int *socket = this->userRegister.getSocket( message->getAdversary_1() );
                if( socket ){

                    this->logoutClient( *socket );
                    delete socket;

                }
            }

        }

        this->matchRegister.setStarted( matchID );
        base<<"-------> [MainServer][acceptHandler] Match "<<matchID<<" started"<<'\n';
        return nullptr;

    }

    //  manages the REJECT requests. It verifies that a match is present and in the correct state then it forwards the reject message
    Message* MainServer::rejectHandler( Message* message, string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][rejectHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        if( !this->cipherServer.fromSecureForm( message, username, this->userRegister.getSessionKey( username ))){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            return this->makeError( string( "Security error. Invalid message'signature" ), nonce );

        }

        base<<"------> [MainServer][rejectHandler] Request has passed signature verification"<<'\n';

        if( message->getAdversary_1().empty() || message->getAdversary_2().empty() ){

            verbose<< "--> [MainServer][acceptHandler] Error, Missing usernames"<<'\n';
            return this->makeError( string( "Invalid request. You have to specify the challenger and challenged usernames" ), nonce );

        }

        int matchID = this->matchRegister.getMatchID( message->getAdversary_1() );
        if( matchID == -1 )
            return nullptr;

        base<<"------> [MainServer][rejectHandler] Identified membership match: "<<matchID<<'\n';
        if( this->sendRejectMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket( message->getAdversary_1()))){

            base<<"------> [MainServer][rejectHandler] REJECT message forwarded to "<<message->getAdversary_1()<<'\n';
            this->userRegister.setLogged( message->getAdversary_1(), this->userRegister.getSessionKey( message->getAdversary_1() ));
            this->matchRegister.removeMatch(matchID);

        }else {

            int* socket = this->userRegister.getSocket( message->getAdversary_1());
            if( socket ) {

                this->logoutClient(*socket);
                delete socket;

            }
            this->matchRegister.removeMatch(matchID);

        }

        return nullptr;

    }

    //  manages the WITHDRAW_REQ requests. It verifies that a match is present and forwards the message
    Message* MainServer::withdrawHandler( Message* message , string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][withdrawHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response = nullptr;

        if( !this->cipherServer.fromSecureForm( message, username, this->userRegister.getSessionKey( username ))){

            verbose << "--> [MainServer][withdrawHandler] Error, Verification failure" << '\n';
            return this->makeError(string( "Security error. Invalid message'signature" ), nonce );

        }

        base<<"------> [MainServer][withdrawHandler] Request has passed signature verification"<<'\n';

        int matchID = this->matchRegister.getMatchID( username );
        if( matchID == -1 ){

            verbose << "--> [MainServer][withdrawHandler] Error, match doesn't exist" << '\n';
            return this->makeError(string( "Invalid request. The match is already deleted" ), nonce );

        }

        base<<"------> [MainServer][withdrawHandler] Identified membership match: "<<matchID<<'\n';

        if( *(this->matchRegister.getMatchStatus( matchID )) == STARTED ){

            verbose << "--> [MainServer][withdrawHandler] Match already started" << '\n';
            return this->makeError(string( "Invalid request. You can't close a started game with withdraw. Use disconnect instead" ), nonce );

        }

        this->userRegister.setLogged( username, this->userRegister.getSessionKey( username ));
        string selUsername = this->matchRegister.getChallenged( matchID );
        if( !selUsername.empty() ) {

            if (!this->sendWithdrawMessage( selUsername, username, this->userRegister.getSocket( selUsername ))) {

                int *socket = this->userRegister.getSocket( selUsername );
                if( socket ){

                    this->logoutClient(*socket);
                    delete socket;

                }

                return nullptr;

            }
        }

        this->matchRegister.removeMatch( matchID );
        this->userRegister.setLogged( username , this->userRegister.getSessionKey(username));

        try {

            response = new Message();
            response->setMessageType(WITHDRAW_OK);
            response->setNonce(*nonce);

        }catch( bad_alloc e ){

            verbose<<"--> [MainServer][withdrawHandler] Error during memory allocation. Operation aborted"<<'\n';
            return this->makeError( string( "Internal Server Error, Try again" ), nonce );

        }

        if( !this->cipherServer.toSecureForm( response, this->userRegister.getSessionKey( username ))){

            verbose << "--> [MainServer][withdrawHandler] Error, Verification failure" << '\n';
            delete response;
            response = this->makeError( string( "Server error. Service unable to generate the message'signature" ), nonce );

        }

        return response;

    }

    //  manages the DISCONNECT requests. It verifies that a match is present and in the correct state then it forwards the message
    Message* MainServer::disconnectHandler( Message* message, string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][disconnectHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        if( !this->cipherServer.fromSecureForm( message, username, this->userRegister.getSessionKey( username ))){

            verbose << "--> [MainServer][disconnectHandler] Error, Verification failure" << '\n';
            return this->makeError(string( "Security error. Invalid message'signature" ), nonce );

        }

        base<<"------> [MainServer][disconnectHandler] Request has passed signature verification"<<'\n';
        string opposite;
        int matchID = this->matchRegister.getMatchID( username );

        if( matchID != -1 )
            opposite = this->matchRegister.getChallenged( matchID );

        else{

            matchID = this->matchRegister.getMatchPlay( username );
            if( matchID != -1 )
                opposite = this->matchRegister.getChallenger(matchID);

            else{

                verbose << "--> [MainServer][disconnectHandler] Error, unable to identify match" << '\n';
                return this->makeError(string( "Invalid request. The match is already closed" ), nonce );

            }
        }

        this->sendDisconnectMessage( opposite );

        this->userRegister.setLogged( username, this->userRegister.getSessionKey( username ));
        this->userRegister.setLogged( opposite, this->userRegister.getSessionKey( opposite ));

        if( this->matchRegister.getTotalMoves( matchID ) > 5 ) {
            base<<"--> [MainServer][disconnectHandler] Disconnection after 5 moves. Penalization applied on :" <<username<<'\n';
            SQLConnector::incrementUserGame(opposite, WIN);
            SQLConnector::incrementUserGame(username, LOOSE);

        }
        this->matchRegister.removeMatch( matchID );
        return nullptr;
    }

    Message* MainServer::gameHandler( Message* message, string username, unsigned int* nonce ){

        if( !message || username.empty() || !nonce ){

            verbose<<"--> [MainServer][gameHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        int matchID = this->matchRegister.getMatchPlay( username );
        if( matchID == -1 ){

            verbose<<"--> [MainServer][gameHandler] Error unable to find match"<<'\n';
            return this->makeError( string( "Invalid request. Match already closed" ), nonce );

        }

        string adversary;
        if( !username.compare(this->matchRegister.getChallenger(matchID)))
            adversary = this->matchRegister.getChallenged(matchID);
        else
            adversary = this->matchRegister.getChallenger(matchID);

        int *advSocket = this->userRegister.getSocket(adversary);

        if( !advSocket ){

            verbose<<"--> [MainServer][gameHandler] Error, Adversary logged out"<<'\n';
            this->userRegister.setLogged(username, this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch( matchID );
            return this->makeError( string( "Error, Adversary is logged out" ), nonce );

        }

        unsigned int *adv_nonce = message->getCurrent_Token();

        if( !adv_nonce ){

            verbose<<"--> [MainServer][gameHandler] Error, Missing Nonce"<<'\n';
            delete advSocket;
            return this->makeError( string( "Security error, Missing nonce"),nonce );

        }

        unsigned int *myNonce = this->clientRegister.getClientReceiveNonce(*advSocket);

        if( !myNonce ){

            this->userRegister.setLogged(adversary, this->userRegister.getSessionKey(adversary));
            this->userRegister.setLogged(username, this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch( matchID );

            delete adv_nonce;
            delete advSocket;
            return this->makeError( string( "Error, user already logged out"), nonce );

        }

        if( *adv_nonce < *myNonce ){

            verbose<<"--> [MainServer][gameHandler] Error, invalid nonce"<<'\n';
            delete adv_nonce;
            delete myNonce;
            delete advSocket;
            return this->makeError( string( "Security error, Invalid nonce"), nonce );

        }


        base<<"------> [MainServer][gameHandler] Request has passed nonce verification"<<'\n';

        this->clientRegister.updateClientReceiveNonce( *advSocket, *adv_nonce+1 );
        delete adv_nonce;
        delete myNonce;

        if( !this->cipherServer.fromSecureForm( message , adversary , this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][gameHandler] Error, Verification failure" << '\n';
            this->sendDisconnectMessage(adversary);
            this->userRegister.setLogged(adversary, this->userRegister.getSessionKey(adversary));
            this->userRegister.setLogged(username, this->userRegister.getSessionKey(username));
            delete advSocket;
            return this->makeError(string( "Security error. Invalid message'signature" ), nonce );

        }
        base<<"------> [MainServer][gameHandler] Request has passed signature verification"<<'\n';

        int col = atoi( string((const char*)message->getChosenColumn(),message->getChosenColumnLength()).c_str());

        if( col<0 || col>= NUMBER_COLUMN ){

            verbose<<"--> [MainServer][gameHandler] Error invalid message column field: "<<col<<'\n';
            this->sendDisconnectMessage(adversary);
            this->userRegister.setLogged(adversary, this->userRegister.getSessionKey(adversary));
            this->userRegister.setLogged(username, this->userRegister.getSessionKey(username));
            verbose<<"--> [MainServer][gameHandler] Applying penalization to the fucking cheater "<<username<<'\n';
            SQLConnector::incrementUserGame( adversary , WIN );
            SQLConnector::incrementUserGame( username, LOOSE );
            this->matchRegister.removeMatch( matchID );
            delete advSocket;
            return this->makeError( string( "Invalid request. Invalid column field" ), nonce );

        }

        int status;

        if( !this->matchRegister.getChallenger(matchID).compare(username))
            status = this->matchRegister.addChallengedMove( matchID, col);
        else
            status = this->matchRegister.addChallengerMove( matchID, col );

        switch( status ){

            case -3:
                return this->makeError( string( "Error, match already closed" ), nonce );

            case -2:
                return this->makeError( string( "Invalid move, It's not your turn" ), nonce );

            case -1:
                return this->makeError( string("Invalid message. Bad Column."), nonce );

            case 1:
                base<<"------> [MainServer][gameHandler] User "<<adversary<<" has won the game"<<'\n';
                SQLConnector::incrementUserGame( adversary , WIN );
                SQLConnector::incrementUserGame( username, LOOSE );
                this->matchRegister.removeMatch( matchID );
                this->userRegister.setLogged( username, this->userRegister.getSessionKey( username ));
                this->userRegister.setLogged( adversary, this->userRegister.getSessionKey( adversary ));
                break;

            case 2:

                base<<"------> [MainServer][gameHandler] Gameboard full, match is concluded with a tie"<<'\n';
                SQLConnector::incrementUserGame( adversary , TIE );
                SQLConnector::incrementUserGame( username, TIE );

                this->userRegister.setLogged(username, this->userRegister.getSessionKey( username ));
                this->userRegister.setLogged( adversary, this->userRegister.getSessionKey( adversary ));
                this->matchRegister.removeMatch(matchID);
                break;

            default: break;
        }

        this->clientRegister.updateClientNonce( *advSocket );
        delete advSocket;
        return nullptr;
    }

}


int main() {

    Logger::setThreshold( VERBOSE );
    MainServer* server = new MainServer( string("127.0.0.1") , 12345 );
    server->server(string("127.0.0.1"));
    return 0;


}





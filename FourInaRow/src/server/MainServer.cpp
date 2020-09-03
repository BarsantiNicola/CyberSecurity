
#include "MainServer.h"


namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    MainServer::MainServer( string ipAddr , int port ){

        this->manager = new utility::ConnectionManager( true , ipAddr.c_str(), port );
        base<<"--> [MainServer][MainServer] Server build completed"<<'\n';

    }

    //  starts the server. The function doesn't return. It will continue until a fatal error happens or the user manually close
    //  the program by Control-C
    void MainServer::server() {

        Message *message;
        Message *response;
        int socket;
        string ipAddr;
        vector<int> waitSockets;
        base<<"--> [MainServer][server] Starting server.."<<'\n';

        if( !this->manager ){
            verbose<<"--> [MainServer][server] Fatal error, unable to find connectionManager"<<'\n';
            return;
        }

        base<<"--> [MainServer][server] Server ready to receive messages"<<'\n';
        while( true ){

            socket = -1;
            ipAddr.clear();
            waitSockets.clear();

            waitSockets = this->manager->waitForMessage( &socket, &ipAddr );


            if( socket != -1 && !ipAddr.empty() ){

                base<<"--> [MainServer][server] New client connection received: "<<socket<<'\n';
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

                    base<<"--> [MainServer][server] Client "<<sock<<" disconnected"<<'\n';
                    this->logoutClient( sock );
                    continue;

                }

                if( message ) {

                    base << "--> [MainServer][server] New message received from client: " << sock << '\n';

                    response = this->manageMessage( message, sock );
                    delete message;

                    bool socketClosed = false;

                    if (response) {
                        if (!this->manager->sendMessage(*response, sock, &socketClosed, nullptr, 0) && socketClosed) {

                            vverbose << "--> [MainServer][server] Error, unable to send message, client " << socket << " disconnected" << '\n';

                            this->logoutClient( sock );

                        }else
                            base << "--> [MainServer][server] Response sent: "<<response->getMessageType()<<'\n';
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

        //  verification of function parameters
        if( !message || socket < 0 ){
            verbose<<"--> [MainServer][manageMessage] Error, missing parameter. Operation Aborted"<<'\n';
            return nullptr;
        }

        base<<"--> [MainServer][manageMessage] Starting base message content verification"<<'\n';
        //  verify the user is not already registered
        if ( !this->clientRegister.has(socket) ) {

            verbose << "--> [MainServer][manageMessage] Error, unregistered socket tried to contact the server" << '\n';
            return this->sendError(string( "UNREGISTERED_SOCK" ), message->getNonce());

        }

        //  CERTIFICATE_REQ and LOGIN_REQ must fail if the user is already logged into the service
        if (!this->userRegister.has(socket) && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ ){

            vverbose << "--> [MainServer][manageMessage] Warning, user not already logged. Invalid request" << '\n';
            return this->sendError(string( "INVALID_REQUEST"), message->getNonce());

        }

        //  verification of the user registration
        string username = this->userRegister.getUsername(socket);
        if (username.empty() && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ ) {

            vverbose << "--> [MainServer][manageMessage] Error, username not found" << '\n';
            return this->sendError(string( "USER_NOT_FOUND" ), message->getNonce());

        }

        Message* response;
        if( message->getMessageType() != CERTIFICATE_REQ ) {

            //  verification of nonce presence
            int *nonce = message->getNonce();
            if ( !nonce ) {

                vverbose << "--> [MainServer][manageMessage] Error, invalid message. Missing Nonce" << '\n';
                return this->sendError(string("MISSING_NONCE"), nonce );

            }

            //  verification of the given nonce with the expected one
            int* userNonce = this->clientRegister.getClientNonce( socket );
            if ( !userNonce ){

                verbose << "--> [MainServer][manageMessage]] Error, user nonce not present" << '\n';
                response = this->sendError(string( "SERVER_ERROR" ), nonce );

                delete nonce;
                return response;

            }

            if( *nonce != *userNonce ){

                vverbose<<"--> [MainServer][keyExchangeHandler] Error invalid nonce"<<'\n';
                response = this->sendError(string( "SECURITY_ERROR" ), nonce );

                delete nonce;
                delete userNonce;
                return response;

            }

            delete userNonce;
            delete nonce;
        }
        base<<"--> [MainServer][manageMessage] Message content verification passed"<<'\n';
        // pass the message to the higher level handler
        response = this->userManager( message, username, socket );

        //  for next message nonce has to be increased
        this->clientRegister.updateClientNonce( socket );
        return response;

    }

    //  the function manages the messages which involve only him and the contacted server(no other clients have to be contacted)
    //  if the function has not the authority to manage the message it passes it to the matchManager to manage it
    Message* MainServer::userManager(Message* message, string username , int socket ) {

        if( !message || socket<0 ){

            verbose<<"--> [MainServer][userManager] Error, missing parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* ret;
        switch( message->getMessageType() ){

            case utility::CERTIFICATE_REQ:
                base<<"--> [MainServer][userManager] Message received: CERTIFICATE_REQ"<<'\n';
                ret = this->certificateHandler(message, socket );
                break;

            case utility::LOGIN_REQ:
                base<<"--> [MainServer][userManager] Message received: LOGIN_REQ"<<'\n';
                ret = this->loginHandler(message, socket );
                break;

            case utility::KEY_EXCHANGE:
                base<<"--> [MainServer][userManager] Message received: KEY_EXCHANGE"<<'\n';
                ret = this->keyExchangeHandler(message, username );
                break;

            case utility::USER_LIST_REQ:
                base<<"--> [MainServer][userManager] Message received: USER_LIST_REQ"<<'\n';
                ret = this->userListHandler(message, username );
                break;

            case utility::RANK_LIST_REQ:
                base<<"--> [MainServer][userManager] Message received: RANK_LIST_REQ"<<'\n';
                ret = this->rankListHandler(message, username );
                break;

            case utility::LOGOUT_REQ:
                base<<"--> [MainServer][userManager] Message received: LOGOUT_REQ"<<'\n';
                ret = this->logoutHandler(message, username, socket );
                break;

            default:
                ret = this->matchManager( message , username );

        }

        return ret;

    }

    Message* MainServer::matchManager(Message* message, string username ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][matchManager] Error, missing parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* ret;

        switch( message->getMessageType() ){

            case utility::MATCH:
                base<<"--> [MainServer][matchManager] Message received: MATCH"<<'\n';
                ret = this->matchHandler( message, username );
                break;

            case utility::ACCEPT:
                base<<"--> [MainServer][matchManager] Message received: ACCEPT"<<'\n';
                ret = this->acceptHandler( message, username );
                break;

            case utility::REJECT:
                base<<"--> [MainServer][matchManager] Message received: REJECT"<<'\n';
                ret = this->rejectHandler( message, username );
                break;

            case utility::WITHDRAW_REQ:
                base<<"--> [MainServer][matchManager] Message received: WITHDRAW_REQ"<<'\n';
                ret = this->withdrawHandler( message, username );
                break;

            case utility::DISCONNECT:
                base<<"--> [MainServer][matchManager] Message received: DISCONNECT"<<'\n';
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

    //  Function to remove a client from the service. The function removes all the pending matches from the client
    //  and then removes it from the service
    void MainServer::logoutClient( int socket ) {

        if( socket < 0 ){
            verbose<<"--> [MainServer][logoutClient] Error, invalid parameter. Undo operation"<<'\n';
            return;
        }

        //  we take all the matches in which the user is involved and we close them
        vector<int> matches = this->matchRegister.getMatchIds( this->userRegister.getUsername( socket ));
        string username = this->userRegister.getUsername( socket );

        for( int matchID: matches )
            this->closeMatch( username, matchID );

        this->userRegister.removeUser( socket );
        this->clientRegister.removeClient( socket );
        base<<"--> [MainServer][logoutClient] Logout of client: "<<socket<<" completed"<<'\n';

    }

    //  Function to securely close a match and inform the other involved client
    void MainServer::closeMatch( string username, int matchID ){

        if( matchID < 0 || username.empty() ){
            verbose<<"--> [MainServer][closeMatch] Error, invalid parameter. Undo operation"<<'\n';
            return;
        }

        string challenged = this->matchRegister.getChallenged(matchID);
        string challenger = this->matchRegister.getChallenger(matchID);

        if( challenged.empty() || challenger.empty() ){

            verbose<<"--> [MainServer][closeMatch] Error, unable to find users"<<'\n';
            return;

        }

        //  if match is started we have to restore client to the LOGGED status
        if( *(this->matchRegister.getMatchStatus( matchID )) == STARTED ){

            this->userRegister.setLogged( challenged, this->userRegister.getSessionKey( challenged ));
            this->userRegister.setLogged( challenger, this->userRegister.getSessionKey( challenger ));

        }

        //  if the user which disconnect is the challenged and the match isn't started we send reject
        if( !challenged.compare(username) && *(this->matchRegister.getMatchStatus( matchID )) == STARTED )
            this->sendRejectMessage( challenger, challenged, this->userRegister.getSocket( challenger ));
        else //  otherwise we send a disconnect to the other client
            if( !challenged.compare(username))
                this->sendDisconnectMessage( challenger );
            else
                this->sendDisconnectMessage( challenged );

        //  finally we remove the match
        this->matchRegister.removeMatch( matchID );

    }

    //  the function generates a random nonce to be given to the clients the perform their requests.
    //  Only nonce derived from the one generated from the server are admitted
    //  for the nonce generation we try three different approaches to obtain a seed
    //  1) usage of urandom file
    //       2) usage of timespec
    //          3) usage of seconds from 1 Jan 1970
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

    //  generates an error message to be sent to the client who has made the request
    Message* MainServer::sendError( string errorMessage, int* nonce ){

        if( errorMessage.empty() ){

            verbose<<"--> [MainServer][sendError] Error invalid arguments. Abort operation"<<'\n';
            return nullptr;

        }

        vverbose<<"--> [MainServer][sendError] Generation of error message: "<<errorMessage<<'\n';

        Message* response = new Message();
        response->setMessageType( ERROR );

        //  for error made into the CERTIFICATE_REQ we generate a one-time nonce
        if( !nonce )
            response->setNonce(generateRandomNonce());
        else
            response->setNonce(*nonce);
        response->setMessage( (unsigned char*)errorMessage.c_str() , errorMessage.length() );

        //  sign the message with a server rsa signature
        if( !this->cipherServer.toSecureForm( response , nullptr )){

            verbose<<"--> [MainServer][sendError] Error unable to secure the message. Operation aborted"<<'\n';
            return nullptr;

        }

        return response;

    }

    // sends directly a message to a given client[used when server has to interact with two clients simultaneously]
    bool  MainServer::sendMessage( Message* message, int socket ){

        if( !message || socket < 0 ){

            verbose<<"--> [MainServer][sendMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        bool socketClosed = false;

        if (!this->manager->sendMessage(*message, socket, &socketClosed, nullptr, 0) && socketClosed) {

            // if the connection with a client is closed we disconnect the user from the service
            vverbose << "--> [MainServer][sendMessage] Error, unable to send message, client " << socket << " disconnected" << '\n';
            this->logoutClient(socket);
            return false;

        }
        return true;
    }

    // sends directly an ACCEPT message to the challenger client
    bool MainServer::sendAcceptMessage( string challenger, string challenged, int* socket ){

        if( challenger.empty() || challenged.empty() || !socket ){

            verbose<<"--> [MainServer][sendAcceptMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        int* nonce = this->userRegister.getNonce(this->userRegister.getUsername(*socket));
        if( !nonce ){

            verbose<<"--> [MainServer][sendAcceptMessage] Error unable to found user nonce. Operation aborted"<<'\n';
            return false;

        }

        Message* message = new Message();
        message->setMessageType( ACCEPT );
        message->setAdversary_1(challenger);
        message->setAdversary_2(challenged);
        message->setNonce(*nonce);

        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(this->userRegister.getUsername(*socket)))){

            verbose<<"--> [MainServer][sendAcceptMessage] Error unable to secure the message. Operation aborted"<<'\n';
            return false;

        }

        return this->sendMessage( message, *socket );

    }

    // sends directly a REJECT message to the challenger client
    bool MainServer::sendRejectMessage( string challenger, string challenged, int* socket ){

        if( challenger.empty() || challenged.empty() || !socket ){

            verbose<<"--> [MainServer][sendRejectMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        int* nonce = this->userRegister.getNonce(this->userRegister.getUsername(*socket));
        if( !nonce ){

            verbose<<"--> [MainServer][sendRejectMessage] Error unable to found user nonce. Operation aborted"<<'\n';
            return false;

        }

        Message* message = new Message();
        message->setMessageType( REJECT );
        message->setAdversary_1(challenger);
        message->setAdversary_2(challenged);
        message->setNonce(*nonce);

        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(this->userRegister.getUsername(*socket)))){

            verbose<<"--> [MainServer][sendRejectMessage] Error unable to secure the message. Operation aborted"<<'\n';
            return false;

        }

        return this->sendMessage( message, *socket );

    }

    // sends directly a DISCONNECT message to a client identified by a username
    bool MainServer::sendDisconnectMessage( string username ){

        if( username.empty()){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        int* socket = this->userRegister.getSocket(username);
        if( !socket ){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error unable to find user socket. Abort operation"<<'\n';
            return false;

        }

        int* nonce = this->userRegister.getNonce(username);
        if( !nonce ){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error unable to find user nonce. Abort operation"<<'\n';
            delete socket;

            return false;

        }

        Message* message = new Message();
        message->setMessageType( DISCONNECT );
        message->setNonce( *nonce );
        delete nonce;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey( username ))){

            verbose<<"--> [MainServer][sendDisconnectMessage] Error unable to secure the message. Operation aborted"<<'\n';
            delete socket;

            return false;

        }

        bool ret = this->sendMessage( message, *socket );
        delete socket;
        return ret;

    }

    // sends directly a GAME_PARAM message to a client identified by a username with the user information of a source
    bool MainServer::sendGameParam( string username , string source ){

        if( username.empty() || source.empty()){

            verbose<<"--> [MainServer][sendGameParam] Error invalid arguments. Abort operation"<<'\n';
            return false;

        }

        int* socket = this->userRegister.getSocket(username);
        if( !socket ){

            verbose<<"--> [MainServer][sendGameParam] Error unable to find user socket. Abort operation"<<'\n';
            return false;

        }

        int* nonce = this->userRegister.getNonce(username);
        if( !nonce ){

            verbose<<"--> [MainServer][sendGameParam] Error unable to find user nonce. Abort operation"<<'\n';
            delete socket;

            return false;

        }

        string param = this->clientRegister.getClientNetInformation( *(this->userRegister.getSocket(source)));
        NetMessage* pubKey = this->cipherServer.getPubKey( source );

        if( !pubKey || param.empty() ){

            verbose<<"--> [MainServer][sendGameParam] Error unable to find user'information. Abort operation"<<'\n';
            delete socket;
            delete nonce;

            return false;

        }

        Message* message = new Message();
        message->setMessageType( GAME_PARAM );
        message->setNonce(*nonce);
        message->setNetInformations( (unsigned char*)param.c_str(), param.length());
        message->setPubKey( pubKey->getMessage(), pubKey->length());

        delete nonce;
        delete pubKey;

        if( !this->cipherServer.toSecureForm( message , this->userRegister.getSessionKey(username ))){

            verbose<<"--> [MainServer][sendGameParam] Error unable to secure the message. Operation aborted"<<'\n';
            delete socket;

            return false;

        }

        bool ret = this->sendMessage( message, *socket );
        delete socket;
        return ret;

    }


    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PROTOCOL HANDLERS                                    //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


    //  the handler manages the CERTIFICATE_REQ requests by generating a formatted message containing the server certificate
    Message* MainServer::certificateHandler( Message* message , int socket ){

        if( !message || socket<0 ){

            verbose<<"--> [MainServer][certificateHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        //  preparation of response message
        NetMessage* param = this->cipherServer.getServerCertificate();
        int nonce = this->generateRandomNonce();

        if(! param ){

            verbose<<"--> [MainServer][certificateHandler] Error, unable to load server certificate"<<'\n';
            return this->sendError( string("SERVER_ERROR"), new int(nonce) );

        }

        this->clientRegister.setNonce( socket, nonce );

        Message* result = new Message();
        result->setNonce( nonce );
        result->setMessageType(CERTIFICATE );
        result->setServer_Certificate( param->getMessage(), param->length());

        delete param;

        if( !this->cipherServer.toSecureForm( result , nullptr )){

            verbose << "--> [MainServer][certificateHandler] Error, message didn't pass security verification" << '\n';
            delete result;
            result = this->sendError(string("SECURITY_ERROR"), new int(nonce) );

        }else
            vverbose<<"--> [MainServer][certificateHandler] CERTIFICATE message correctly generated"<<'\n';

        return result;

    }

    //  the handler manages the LOGIN_REQ requests verifying if the user is already registered and its signature is valid
    Message* MainServer::loginHandler( Message* message , int socket ){

        if( !message || socket<0 ){

            verbose<<"--> [MainServer][loginHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        //  nonce presence has already been verified in low level functions
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

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][keyExchangeHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response;
        int *nonce = message->getNonce();

        if( !this->cipherServer.fromSecureForm( message, username, nullptr )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, message didn't pass the security checks" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        vverbose << "--> [MainServer][keyExchangeHandler] Request has passed security checks" << '\n';
        NetMessage* param = this->cipherServer.getPartialKey();
        if( !param ){

            verbose<<"--> [MainServer][keyExchangeHandler] Error unable to generate diffie-hellman parameter"<<'\n';
            return nullptr;

        }

        //  nonce presence has already been verified in low level functions

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

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][userListHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        Message* response;
        int *nonce = message->getNonce();
        if( !this->cipherServer.fromSecureForm( message, message->getUsername(), this->userRegister.getSessionKey(username) )){

            verbose<<"--> [MainServer][userListHandler] Error. Verification Failure"<<'\n';
            response = this->sendError( string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        if( *(this->userRegister.getStatus( username )) != LOGGED ){

            verbose << "--> [MainServer][userListHandler] Error, user not allowed" << '\n';
            response = this->sendError(string("INVALID_REQUEST"), nonce );

            delete nonce;
            return response;

        }

        vverbose << "--> [MainServer][userListHandler] Request has passed security checks" << '\n';
        NetMessage *user_list = this->userRegister.getUserList( username );

        if( !user_list ){

            verbose<<"--> [MainServer][userListHandler] Error unable to obtain the user list"<<'\n';
            return nullptr;

        }

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

    //  the handler manages the RANK_LIST_REQ requests. After it has verified the message consistency it generates
    //  a message containing a formatted list of all the users game statistics mantained in a remote MySQL server
    Message* MainServer::rankListHandler( Message* message  , string username ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][rankListHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        //  nonce presence has already been verified in low level functions
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

        if( rank_list.empty() ){

            verbose<<"--> [MainServer][rankListHandler] Error unable to obtain users statistics"<<'\n';
            return nullptr;

        }

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

    //  the handler manages LOGOUT_REQ requests. It closes any pending match then it securely delete the user from the service
    Message* MainServer::logoutHandler( Message* message , string username, int socket ){

        if( !message || username.empty() || socket<0 ){

            verbose<<"--> [MainServer][logoutHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        //  nonce presence has already been verified in low level functions
        int* nonce = message->getNonce();
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


        if( !this->cipherServer.toSecureForm( response, this->userRegister.getSessionKey(username) )){

            verbose << "-->[MainServer][logoutHandler] Error. Unable to encrypt message"<< '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        this->logoutClient( socket );

        delete nonce;
        return response;

    }

    //  manages the MATCH requests. It verifies the users are in the correct states and have the correct information to start a match
    Message* MainServer::matchHandler( Message* message, string username ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][matchHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

        int* nonce = message->getNonce();

        Message* response;
        if( !this->cipherServer.fromSecureForm( message , username, this->userRegister.getSessionKey(username) ) ){

            verbose << "--> [MainServer][matchHandler] Error, Verification failure" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;
        }

        if( message->getUsername().empty() ){

            verbose<<"--> [MainServer][matchHandler] Error missing user informations"<<'\n';
            return this->sendError( "MISSING USERNAMES", nonce );

        }

        if( this->matchRegister.getMatchID(username) != -1 ){

            verbose<<"--> [MainServer][matchHandler] Error, user already has registered a match"<<'\n';
            response = this->sendError(string( "INVALID_REQUEST" ), nonce );

            delete nonce;
            return response;

        }

        if( *(this->userRegister.getStatus(message->getUsername()) ) == CONNECTED || *(this->userRegister.getStatus(message->getUsername())) == PLAY ){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';
            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );
            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }

            delete nonce;
            return response;

        }

        int* adv_socket = this->userRegister.getSocket( message->getUsername() );
        int* adv_nonce =  this->userRegister.getNonce( message->getUsername() );
        cipher::SessionKey* userKey = this->userRegister.getSessionKey( message->getUsername());

        if( !adv_socket || !adv_nonce || !userKey ){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';

            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey(username) )){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }

            delete userKey;
            delete adv_socket;
            delete adv_nonce;
            delete nonce;
            return response;

        }

        if( !this->matchRegister.addMatch( username, message->getUsername())){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';

            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError( string( "SERVER_ERROR" ), nonce );

            }

            delete userKey;
            delete adv_socket;
            delete adv_nonce;
            delete nonce;
            return response;

        }

        this->userRegister.setWait( username );

        response = new Message();
        response->setMessageType( MATCH );
        response->setUsername( username );
        response->setNonce( *adv_nonce );

        if( !this->cipherServer.toSecureForm( response , userKey )){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';
            this->userRegister.setLogged( username, this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch(this->matchRegister.getMatchID(username));

            delete response;
            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }

            delete userKey;
            delete adv_socket;
            delete adv_nonce;
            delete nonce;
            return response;

        }

        if( !this->sendMessage( response , *adv_socket )){

            verbose<<"--> [MainServer][matchHandler] Error, challenged unable to accept match requests"<<'\n';
            this->userRegister.setLogged( username , this->userRegister.getSessionKey(username));
            this->matchRegister.removeMatch(this->matchRegister.getMatchID(username));

            delete response;
            response = new Message();
            response->setMessageType( REJECT );
            response->setAdversary_1( username );
            response->setAdversary_2( message->getUsername() );
            response->setNonce( *nonce );

            if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( username ))){

                verbose<<"--> [MainServer][matchHandler] Error during security conversion"<<'\n';
                delete response;
                response = sendError(string("SERVER_ERROR"), nonce );

            }

            delete adv_socket;
            delete adv_nonce;
            delete userKey;
            delete nonce;
            return response;

        }

        delete adv_socket;
        delete adv_nonce;
        delete userKey;
        delete nonce;
        return nullptr;

    }

    //  manages the ACCEPT requests. It verifies that a match is present and in the correct state
    Message* MainServer::acceptHandler( Message* message , string username ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][acceptHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

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
            delete nonce;
            return response;

        }

        if( *(this->userRegister.getStatus( username )) != LOGGED ){

            verbose<< "--> [MainServer][acceptHandler] Error, user try to accept a challenge before undo previous sent"<<'\n';
            response = this->sendError( "WRONG_STATE" , nonce );
            delete nonce;
            return response;

        }

        int matchID = this->matchRegister.getMatchID( message->getAdversary_1() );

        if( matchID == -1 ){

            verbose<<"--> [MainServer][acceptHandler] Error, match doesn't exists"<<'\n';
            response = new Message();
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

        if( this->sendAcceptMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket( message->getAdversary_1()))){

            this->userRegister.setPlay(message->getAdversary_1());
            this->userRegister.setPlay(message->getAdversary_2());
            this->matchRegister.setAccepted( matchID );

            vector<int> matches = this->matchRegister.getMatchIds( username );
            for( int match: matches )
                if( match != matchID )
                    this->closeMatch( username, match );

        }else {

            int* socket = this->userRegister.getSocket( message->getAdversary_1());
            if( socket ) {
                this->logoutClient(*socket);
                delete socket;
                return nullptr;

            }else {

                verbose << "--> [MainServer][acceptHandler] Something goes wrong. Server repair" << '\n';
                this->matchRegister.removeMatch(matchID);

            }

            response = new Message();
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

        if( !this->sendGameParam( message->getAdversary_1(), message->getAdversary_2())){


            int* socket = this->userRegister.getSocket( message->getAdversary_1());
            if( socket ) {

                this->logoutClient(*socket);
                delete socket;
                return nullptr;

            }else {

                verbose << "--> [MainServer][acceptHandler] Something goes wrong. Server repair" << '\n';
                this->matchRegister.removeMatch(matchID);

            }
            this->userRegister.setLogged( username, this->userRegister.getSessionKey( username ));

            response = new Message();
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

        if( !this->sendGameParam( message->getAdversary_2(), message->getAdversary_1())){


            int* socket = this->userRegister.getSocket( message->getAdversary_2());
            if( socket ) {

                this->logoutClient(*socket);
                delete socket;
                return nullptr;

            }else {

                verbose << "--> [MainServer][acceptHandler] Something goes wrong. Server repair" << '\n';
                this->matchRegister.removeMatch(matchID);

            }
            this->userRegister.setLogged( message->getAdversary_1(), this->userRegister.getSessionKey( message->getAdversary_1()));

            if(!this->sendRejectMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket(message->getAdversary_1()))) {
                int *socket = this->userRegister.getSocket(message->getAdversary_1());
                if (socket) {
                    this->logoutClient(*socket);
                    delete socket;
                }
            }

        }

        delete nonce;
        return nullptr;

    }

    //  manages the REJECT requests. It verifies that a match is present and in the correct state
    Message* MainServer::rejectHandler( Message* message , string username ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][rejectHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

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

        if( matchID == -1 )
            return nullptr;

        if( this->sendRejectMessage( message->getAdversary_1(), message->getAdversary_2(), this->userRegister.getSocket( message->getAdversary_1()))){

            this->userRegister.setLogged(message->getAdversary_1(), this->userRegister.getSessionKey(message->getAdversary_1()));
            this->matchRegister.removeMatch(matchID);
            return nullptr;

        }else {

            int* socket = this->userRegister.getSocket( message->getAdversary_1());
            if( socket ) {
                this->logoutClient(*socket);
                delete socket;
            }

            return nullptr;

        }

    }

    Message* MainServer::withdrawHandler( Message* message , string username ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][rejectHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }

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
        if( selUsername.empty() )
            return nullptr;

        if( !this->sendDisconnectMessage( selUsername )){

            int* socket = this->userRegister.getSocket(selUsername);
            if( socket ){

                this->logoutClient( *socket );
                delete socket;

            }
            delete nonce;
            return nullptr;

        }

        this->matchRegister.removeMatch( matchID );
        this->userRegister.setLogged( username , this->userRegister.getSessionKey(username));

        if( !this->cipherServer.toSecureForm( response , this->userRegister.getSessionKey( selUsername ))){

            verbose << "--> [MainServer][acceptHandler] Error, Verification failure" << '\n';
            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

            delete nonce;
            return response;

        }

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

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][disconnectHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }
        return nullptr;
    }

    Message* MainServer::gameHandler( Message* message, string username ){

        if( !message || username.empty() ){

            verbose<<"--> [MainServer][gameHandler] Error invalid parameters. Operation Aborted"<<'\n';
            return nullptr;

        }
        /*
        int matchID = this->matchRegister.getMatchPlay( username );
        int *nonce = message->getNonce();
        int* col = message->getC
        Message* response;

        if( matchID == -1 ){

            verbose<<"--> [MainServer][gameHanlder] Error unable to find match"<<'\n';
            response = this->sendError( "MISSING MATCH", nonce );
            delete nonce;
            return response;

        }

        if( !this->matchRegister.getChallenger(matchID).compare(username))
            this->matchRegister.addChallengerMove( matchID, message->getC)*/
        return nullptr;
    }

}

int main() {

    Logger::setThreshold( VERBOSE );
    MainServer* server = new MainServer( string("127.0.0.1") , 12345 );
    server->server();
    return 0;


}





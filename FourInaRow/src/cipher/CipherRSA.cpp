
#include "CipherRSA.h"
#include "../Logger.h"

namespace cipher{

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                   COSTRUCTORS/DESTRUCTORS                                 //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  costructor used for both the client and the server. To adapt it's functioning use the bool server argument
    CipherRSA::CipherRSA( string username, string password, bool server ) {

        this->server = server;
        this->advPubKey = nullptr;
        this->serverCertificate = nullptr;
        this->lenServerCertificate = 0;
        this->myPubKey = nullptr;
        this->myPrivKey = nullptr;
        this->pubServerKey = nullptr;

        if( server ){

            vverbose<<"--> [CipherRSA][Costructor] Searching server certificate.."<<'\n';
            std::ifstream certRead;
            certRead.open("data/server_data/serverCertificate.pem");
            if( !certRead ){
                verbose<<"--> [CipherRSA][Costructor] Fatal Error. Unable to find: data/server_data/serverCertificate.pem"<<'\n';
                return;
            }

            vverbose<<"--> [CipherRSA][Costructor] Certificate found, starting loading"<<'\n';
            certRead.seekg( 0, std::ios::end );
            this->lenServerCertificate = certRead.tellg();
            certRead.seekg( 0, std::ios::beg );
            this->serverCertificate = new unsigned char[this->lenServerCertificate];
            if( !this->serverCertificate ){
                verbose<<"--> [CipherRSA][Costruction] Fatal error. Unable to allocate memory"<<'\n';
                certRead.close();
                return;
            }
            certRead.read( (char*)this->serverCertificate, this->lenServerCertificate );
            certRead.close();
            vverbose<<"--> [CipherRSA][Costructor] Certificate correctly loaded."<<'\n';

        }

        FILE* publicKey, *privateKey;
        vverbose<<"--> [CipherRSA][Costructor] Searching "<<username<<"'RSA keys"<<'\n';

        if( server ) {

            string privKey = "data/server_data/";
            privKey.append(username).append( "PrivRSA.pem" );

            string pubKey = "data/server_data/";
            pubKey.append(username).append("PubRSA.pem");

            publicKey = fopen( pubKey.c_str() ,"r");
            privateKey = fopen( privKey.c_str() , "r" );

        }else {

            string privKey = "data/client_data/";
            privKey.append(username).append("PrivRSA.pem");

            string pubKey = "data/client_data/";
            pubKey.append(username).append("PubRSA.pem");
            publicKey = fopen(pubKey.c_str(), "r");
            privateKey = fopen(privKey.c_str(), "r");

        }

        if( !publicKey || !privateKey ){

            verbose<<"--> [CipherRSA][Costructor] Error "<<username<<" undefined, keys not found"<<'\n';
            throw 0;
        }else{
            vverbose<<"--> [CipherRSA][Costructor] "<<username<<"'keys found"<<'\n';

            this->myPubKey = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);


            if( ! this->myPubKey ) {
                verbose << "--> [CipherRSA][Costructor] Unable to extract " << username << " public key" << '\n';
                fclose(publicKey);
                fclose(privateKey);
                throw 0;
            }else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" public key correctly loaded"<<'\n';
            fclose(publicKey);


            this->myPrivKey = PEM_read_PrivateKey( privateKey, nullptr, nullptr , (void*)password.c_str());
            if( ! this->myPrivKey ) {
                verbose << "--> [CipherRSA][Costructor] Unable to extract " << username << " private key" << '\n';
                fclose(privateKey);
                throw 1;
            }else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" private key correctly loaded"<<'\n';
            fclose(privateKey);

        }

    }

    CipherRSA::~CipherRSA(){

        if( myPubKey ) {
            EVP_PKEY_free(this->myPubKey);
            this->myPubKey = nullptr;
        }

        if( myPrivKey ) {
            EVP_PKEY_free(this->myPrivKey);
            this->myPrivKey = nullptr;
        }

        if( advPubKey ) {
            EVP_PKEY_free(this->advPubKey);
            this->advPubKey = nullptr;
        }

      /*  if( pubServerKey ) {
            EVP_PKEY_free(this->pubServerKey);
            this->pubServerKey = nullptr;
        }*/

        if( !keyArchive.empty() ) {

            for (auto const &element : keyArchive)
                EVP_PKEY_free(element.second);
            keyArchive.clear();

        }
        vverbose<<"--> [CipherRSA][Destructor] Object destroyed"<<'\n';

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                     PRIVATE FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  Function of utility to the generation of a message signature. It takes a compact form of the Message class and
    //  using an RSA private key gives in return a signature. It will return NULL if fail
    unsigned char* CipherRSA::makeSignature( unsigned char* compactMessage, unsigned int& len, EVP_PKEY* key  ){

        if( !compactMessage || !key || !len ){
            verbose<<"-->[CipherRSA][makeSignature] Error, invalid arguments"<<'\n';
            return nullptr;
        }

        unsigned int l = len;
        unsigned char* signature;
        signature = (unsigned char*)malloc( EVP_PKEY_size(key));
        if( !signature ){
            verbose<<"-->[CipherRSA][makeSignature] Error during the allocation of the memory"<<'\n';
        }
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_SignInit(ctx,EVP_sha256());
        EVP_SignUpdate( ctx, compactMessage, l);
        EVP_SignFinal(ctx,signature,(unsigned int*)&l,key);
        EVP_MD_CTX_free(ctx);
        len = l;
        vverbose<<"-->[CipherRSA][makeSignature] Signature generated"<<'\n';

        return signature;

    }

    //  Function of utility to verify a signature. It takes a compact form of the Message class, the given signature and a public key.
    bool CipherRSA::verifySignature( unsigned char* compactMessage , unsigned char* signature , int compactLen, int signatureLen, EVP_PKEY* key ){

        if( !compactMessage || !signature || !compactLen || !signatureLen || !key ){
            verbose<<"--> [CipherRSA][verifySignature] Error, invalid arguments"<<'\n';
            return false;
        }
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_VerifyInit(ctx,EVP_sha256());
        EVP_VerifyUpdate(ctx,compactMessage, compactLen );
        if( EVP_VerifyFinal(ctx,signature,signatureLen,key) != 1 ){
            verbose<<"-->[CipherRSA][verifySignature] Authentication Error!"<<'\n';
            EVP_MD_CTX_free(ctx);
            return false;
        }

        verbose<<"-->[CipherRSA][verifySignature] Authentication Success!"<<'\n';
        EVP_MD_CTX_free(ctx);
        return true;

    }
    
    bool CipherRSA::certificateVerification( Message* message, EVP_PKEY* key ){

        if( message == nullptr || key == nullptr ){
            verbose<<"--> [CipherRSA][certificateVerification] Error, invalid parameters"<<'\n';
            return false;
        }

        if( message->getMessageType() != CERTIFICATE){
            verbose<<"--> [CipherRSA][certificateVerification] Error, function made only for certificate verification"<<'\n';
            return false;
        }

        NetMessage* compact = Converter::compactForm( message->getMessageType(), *message);
        if( compact == nullptr){
            verbose<<"--> [CipherRSA][certificateVerification] Error, unable to compact message"<<'\n';
            return false;
        }

        bool ret = CipherRSA::verifySignature(compact->getMessage(), message->getSignature(), compact->length(), message->getSignatureLen(),key);
        delete compact;
        return ret;
    }

    //  Function of utility to verify a certificate. It can be used only in a CipherRSA made with the server=false in the costructor.
    bool CipherRSA::verifyCertificate(X509* certificate){

        if( !certificate ){
            verbose<<"--> [CipherRSA][verifyCertificate] Error, null-pointer passed as argument"<<'\n';
            return false;
        }
        vverbose<<"--> [CipherRSA][verifyCertificate] Searching CA certificate and CRL.."<<'\n';
        X509* caCertificate;
        X509_CRL* crl;
        FILE* certFile = fopen( "data/client_data/caCertificate.pem", "r" );

        if( !certFile ){
            verbose<<"--> [CipherRSA][verifyCertificate] Fatal Error. Unable to find: data/client_data/caCertificate.pem"<<'\n';
            throw -1;
        }

        caCertificate = PEM_read_X509( certFile, nullptr, nullptr, nullptr );
        if( !caCertificate ){
            verbose<<"--> [CipherRSA][verifyCertificate] Fatal error. Unable to load the ca certificate"<<'\n';
            fclose( certFile );
            throw -1;
        }

        fclose( certFile );
        vverbose<<"--> [CipherRSA][verifyCertificate] Certificate found"<<'\n';

        certFile = fopen( "data/client_data/caCrl.pem", "r" );
        if( !certFile ){
            verbose<<"--> [CipherRSA][verifyCertificate] Fatal Error. Unable to find the file data/client_data/caCrl.pem"<<'\n';
            throw -1;
        }

        crl = PEM_read_X509_CRL( certFile, nullptr, nullptr, nullptr );
        if( !crl ){
            verbose<<"--> [CipherRSA][verifyCertificate] Fatal error. Unable to load the ca CRL"<<'\n';
            fclose( certFile );
            throw -1;
        }
        fclose( certFile );
        vverbose<<"--> [CipherRSA][verifyCertificate] CRL found"<<'\n';
        X509_STORE* store = X509_STORE_new();
        vverbose<<"--> [CipherRSA][verifyCertificate] Starting generation of keyStore"<<'\n';

        if( !store ){
            verbose<<"--> [CipherRSA][verifyCertificate] Fatal Error. Unable to create the keyStore"<<'\n';
            throw -1;
        }

        X509_STORE_add_cert(store,caCertificate);
        X509_STORE_add_crl(store,crl);
        X509_STORE_set_flags( store , X509_V_FLAG_CRL_CHECK );
        vverbose<<"--> [CipherRSA][verifyCertificate] Keystore correctly created"<<'\n';

        X509_STORE_CTX* ctx = X509_STORE_CTX_new();
        if( !ctx ){
            verbose<<"--> [CipherRSA][verifyCertificate] Error, unable to create a X509 store"<<'\n';
            return false;
        }

        X509_STORE_CTX_init(ctx,store,certificate,NULL);

        int ret = X509_verify_cert(ctx);
        if( ret!= 1 ){
            verbose<<"--> [CipherRSA][verifyCertificate] Fatal error, certificate unknown"<<'\n';
            return false;
        }

        vverbose<<"--> [CipherRSA][verifyCertificate] Certificate verified"<<'\n';
        return true;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                     PUBLIC FUNCTIONS                                      //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  SERVER
    //  Function used by the server to insert a user key into its archive. It needs to be called on login of a user
    bool CipherRSA::loadUserKey( string username ) {

        vverbose <<"--> [CipherRSA][loadUserKey] Loading of " <<username<<"' public key"<<'\n';

        if( keyArchive.find( username ) != keyArchive.end()){
            verbose<<"--> [CipherRSA][loadUserKey] Key already loaded. Abort"<<'\n';
            return true;
        }

        string pubKey = "data/server_data/";
        pubKey.append(username).append( "PubRSA.pem" );

        FILE* publicKey = fopen( pubKey.c_str() ,"r");

        if( !publicKey  ) {

            verbose << "--> [CipherRSA][loadUserKey] Error, key not found" << '\n';
            return false;

        }else{

            vverbose<<"--> [CipherRSA][loadUserKey] "<<username<<"'keys found"<<'\n';

            EVP_PKEY* key = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);
            if( ! key  ) {
                verbose << "--> [CipherRSA][loadUserKey] Unable to extract " << username << "'public key" << '\n';
                EVP_PKEY_free(key);
                fclose(publicKey);
                return false;
            }else
                vverbose<<"--> [CipherRSA][loadUserKey] " << username<<"'public key correctly loaded"<<'\n';

            fclose(publicKey);
            this->keyArchive[username] = key;
            return true;

        }

    }

    // SERVER
    //  Function used by the server to remove a user key from its archive. It will be used on the logout of a user
    bool CipherRSA::removeUserKey( string username ){

        if( keyArchive.find( username ) == keyArchive.end()){
            verbose<<"--> [CipherRSA][removeUserKey] Key not present. Abort"<<'\n';
            return true;
        }

        if( keyArchive.erase( username )) {
            vverbose<<"--> [CipherRSA][removeUserKey] "<<username<<"'key correctly removed"<<'\n';
            return true;
        }else{
            verbose<<"--> [CipherRSA][removeUserKey] Error during the removal of the "<<username<<"'key"<<'\n';
            return false;
        }

    }

    //  SERVER
    //  Gives the key of a logged user by searching into its archive
    EVP_PKEY* CipherRSA::getUserKey( string username ){

        if( keyArchive.find(username) == keyArchive.end() ){
            verbose<<"--> [CipherRSA][getUserKey] Error, "<<username<<"'key not present"<<'\n';
            return nullptr;
        }

        auto it = keyArchive.find(username);

        vverbose <<"--> [CipherRSA][getUserKey] Key of " <<username<<" found"<<'\n';
        return it->second;

    }

    // SERVER
    //  Verify the signature of a message received by the server
    bool CipherRSA::serverVerifySignature( Message message, string username ){


        EVP_PKEY* key = getUserKey(username);
        if( !key ){
            verbose<<"-->[CipherRSA][serverVerifySignature] Error, "<<username<<"'key not found"<<'\n';
            return false;
        }
        unsigned char* signature = message.getSignature();
        bool ret;
        if( !signature ){
            verbose<<"-->[CipherRSA][serverVerifySignature] Error, message hasn't a signature"<<'\n';
            return false;
        }

        NetMessage* compactMessage = Converter::compactForm(message.getMessageType() , message );
        if( compactMessage == nullptr || compactMessage->length() == 0 ){
            verbose<<"-->[CipherRSA][serverVerifySignature] Error during the generation of the compact message"<<'\n';
            delete[] signature;
            return false;
        }

        ret = verifySignature( compactMessage->getMessage() , signature , compactMessage->length() , message.getSignatureLen(), key );

        delete[] signature;
        delete compactMessage;
        return ret;

    }

    // CLIENT
    //  Verify the signature of a message received by a client
    bool CipherRSA::clientVerifySignature( Message message , bool server ){

        unsigned char* signature = message.getSignature();
        bool ret;
        if( !signature ){
            verbose<<"-->[CipherRSA][clientVerifySignature] Error, message hasn't a signature"<<'\n';
            return false;
        }

        NetMessage* compactMessage = Converter::compactForm(message.getMessageType() , message );
        if( compactMessage == nullptr || compactMessage->length() == 0 ){
            verbose<<"-->[CipherRSA][clientVerifySignature] Error during the generation of the compact message"<<'\n';
            delete[] signature;
            return false;
        }

        if( server )
            ret = verifySignature( compactMessage->getMessage() , signature , compactMessage->length() , message.getSignatureLen(), this->pubServerKey );
        else
            ret = verifySignature( compactMessage->getMessage() , signature , compactMessage->length() , message.getSignatureLen(), this->advPubKey );

        delete[] signature;
        delete compactMessage;
        return ret;

    }

    //  CLIENT
    //  Set an adversary key if another is already being used.
    bool CipherRSA::setAdversaryKey( EVP_PKEY* Key ){

        if( this->advPubKey ){
            verbose<<"-->[CipherRSA][setAdversaryKey] Error, adversary key already setted[USE unsetAdversaryKey before]"<<'\n';
            return false;
        }

        if( !Key ){
            verbose<<"-->[CipherRSA][setAdversaryKey] Error, null pointer passed as argument"<<'\n';
            return false;
        }

        this->advPubKey = Key;
        return true;

    }

    // CLIENT
    // Unset the adversary key of the user if is has one.
    void CipherRSA::unsetAdversaryKey(){

        if( this->advPubKey != nullptr ) {
            verbose<<"-->[CipherRSA][unsetAdversaryKey] Error, adversary key not setted[USE setAdversaryKey before]"<<'\n';
            EVP_PKEY_free(this->advPubKey);
        }
        this->advPubKey = nullptr;

    }

    //  CLIENT
    //  Validate a certificate(taken from Message.certificate field) and if it is the server extract the public key
    EVP_PKEY* CipherRSA::extractServerKey( unsigned char* certificate , int len ){

        if( !certificate || !len ){

            verbose<<"-->[CipherRSA][extractServerKey] Error, invalid arguments"<<'\n';
            return nullptr;

        }
        vverbose<<"-->[CipherRSA][extractServerKey] Starting verification of certificate"<<'\n';

        std::ofstream pemWrite("data/temp/serverCertificate.pem");
        X509* cert;

        pemWrite.write((char*)certificate,len);
        pemWrite.close();

        FILE* f = fopen("data/temp/serverCertificate.pem" , "r");
        if(!f){
            verbose<<"-->[CipherRSA][extractServerKey] Error. File not found"<<'\n';
            return nullptr;
        }

        cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
        fclose(f);
        remove("data/temp/serverCertificate.pem");

        if( !cert ){
            verbose<<"-->[CipherRSA][extractServerKey] Error, unable to perform certificate analysis"<<'\n';
            return nullptr;
        }

        if( CipherRSA::verifyCertificate(cert)) {
            vverbose<<"-->[CipherRSA][extractServerKey] Extraction of the public key"<<'\n';
            return X509_get_pubkey(cert);
        }

        return nullptr;

    }

    bool CipherRSA::setServerKey( EVP_PKEY* server ){

        if( this->pubServerKey ) return false;
        this->pubServerKey = server;
        return true;

    }

    //  CLIENT
    //  Extract the public key from what its textual form given with message
    bool CipherRSA::extractAdversaryKey( unsigned char* pubKey , int len ){

        if( !pubKey || !len ){

            verbose<<"-->[CipherRSA][extractAdversaryKey] Error, invalid arguments"<<'\n';
            return false;

        }

        std::ofstream pemWrite("data/temp/advKey.pem");
        pemWrite.write((char*)pubKey,len);
        pemWrite.close();

        FILE* f = fopen("data/temp/advKey.pem" , "r");
        EVP_PKEY* k = PEM_read_PUBKEY( f, nullptr, nullptr, nullptr );
        fclose(f);
        remove("data/temp/advKey.pem");

        if( !k ){
            verbose<<"-->[CipherRSA][extractAdversaryKey] Error, unable to extract adversary public key"<<'\n';
            return false;
        }

        this->advPubKey = k;
        return true;
    }


    //  COMMON
    //  Generate a compact form of the message to generate a signature of validity. Then it insert it into the given message
    bool CipherRSA::sign( Message* message ){

        NetMessage* compactForm = Converter::compactForm( message->getMessageType() , *message );
        if( !compactForm ) {
            verbose << "-->[CipherRSA][sign] Error during the generation of the compact Form of the message" << '\n';
            return false;
        }

        unsigned int len = compactForm->length();
        unsigned char *signature = makeSignature( compactForm->getMessage() , len, this->myPrivKey );

        message->setSignature( signature, len );

        delete compactForm;
        delete[] signature;
        return true;

    }

    bool CipherRSA::test(){

        CipherRSA* client = new CipherRSA( "bob" , "bobPassword", false);
        CipherRSA* server = new CipherRSA( "server" , "serverPassword" , true );

        base<<"----------------SERVER KEY EXCHANGE--------------------"<<'\n';

        Message* message = new Message();
        message->setNonce(14);
        message->setServer_Certificate( server->serverCertificate, server->lenServerCertificate );
        message->setMessageType( CERTIFICATE );
        server->sign(message);

        NetMessage* net = Converter::encodeMessage(CERTIFICATE, *message );
        delete message;

        //  SENDING ON THE NETWORK

        message = Converter::decodeMessage(*net);
        delete net;

        if( ! client->extractServerKey( message->getServerCertificate() , message->getServerCertificateLength())){
            verbose<<"-->[CipherRSA][test] Error, unable to extract server key"<<'\n';
            return false;
        }
        if( !client->clientVerifySignature(*message,true))
            return false;

        return true;
    }

    NetMessage* CipherRSA::getServerCertificate() {
        if( !this->server ){
            verbose<<"-->[CipherRSA][getServerCertificate] Error, not setted as server"<<'\n';
            return nullptr;
        }
        return new NetMessage( this->serverCertificate, this->lenServerCertificate );

    }

    EVP_PKEY* CipherRSA::getPubKey() {
        return this->myPubKey;
    }

}

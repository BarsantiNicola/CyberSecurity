
#ifndef FOURINAROW_CIPHERSERVER_H
#define FOURINAROW_CIPHERSERVER_H

#include "CipherRSA.h"
#include "CipherDH.h"
#include "CipherAES.h"
#include "../Logger.h"
#include "../utility/Message.h"
#include "../utility/NetMessage.h"

using namespace utility;

namespace cipher {

    //////////////////////////////////////////////////////////////////////////////////////
    //                                                                                  //
    //                                   CIPHERSERVER                                   //
    //    The class is a container of classes implemented into the cipher package. It   //
    //    implements an interface for the server::MainServer class to easily interact   //
    //    with the cipher methods. It permits to:                                       //
    //                                                                                  //
    //        - convert a message to a secure domain(encryption, signatures applied)    //
    //        - convert a message from the secure domain(decrypt messages, verification //
    //          and removal of signatures)                                              //
    //        - extract keys from pem format                                            //
    //        - manage RSA keys of all the service users                                //
    //        - generate session keys with Diffie-Hellman algorithm                     //
    //                                                                                  //
    //////////////////////////////////////////////////////////////////////////////////////

    class CipherServer {

        private:
            CipherRSA* rsa;            //  manages RSA key extraction, message signature and verification
            CipherDH*  dh;             //  manages Diffie-Hellman key generation
            CipherAES* aes;            //  manages AES encryption and message signature and verification

        public:
            CipherServer();
            ~CipherServer();
            bool toSecureForm( Message* message, SessionKey* aesKey );           //  convert a message to the secure domain(apply signatures and encryption basing on the message Type)
            bool fromSecureForm( Message* message , string username , SessionKey* aesKey );  //  convert a message from the secure domain(decrypt and verify and removes signature basing on the message Type)
            NetMessage* getServerCertificate();                                  //  extract and return the server certificate maintained into the file-system
            NetMessage* getPartialKey();                                         //  starts the diffie-hellman algorithm for generating an AES sessionKey and its parameters
            SessionKey* getSessionKey( unsigned char* param, unsigned int len ); // ends the diffie-hellman algorithm creating an AES sessionKey and its parameters
            NetMessage* getPubKey( string username );                            // search, extract and return a user certificate from that available into the file-system

    };

}


#endif //FOURINAROW_CIPHERSERVER_H

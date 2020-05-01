
#ifndef CIPHER_AES_H
#define CIPHER_AES_H

#include <iostream>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include "Message.h"
#include "NetMessage.h"


using namespace std;

class cipherAES{
	
	private:
		unsigned char* key;
		
	public:
		NetMessage* encryptMessage( Message );
		Message* decryptMessage( NetMessage );
		cipherAES( const char[] );
};

#endif
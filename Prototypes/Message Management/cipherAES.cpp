#include "cipherAES.h"


cipherAES::cipherAES( const char key[] ){
	
	this -> key = (unsigned char*) key;
	
}

NetMessage* cipherAES::encryptMessage( Message msg ){
	
	NetMessage* message = msg.stringify();  //  get a string encoding of the message
	
	char* txt = message->getMessage();      //  get the message

	int oLen,cLen;
	unsigned char* cTxt;
	
	EVP_CIPHER_CTX* ctx;
	
	if( key == NULL || message->getMessage() == NULL || message->length() < 1 ){
		cout<<"[cipherAES] Error during the encryption of the message"<<endl;
		return NULL;
	}
	
	cTxt = (unsigned char*)malloc( message->length() + 16 );
	
	if( cTxt == NULL ){
		cout<<"[cipherAES] Error during the allocation of memory";
		return NULL;
	}
	
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit( ctx, EVP_aes_256_cbc(), key , NULL );
	EVP_EncryptUpdate( ctx, cTxt , &oLen , (unsigned char*)message->getMessage() , message->length() );
	cLen = oLen;
	EVP_EncryptFinal( ctx , cTxt + cLen, &oLen );
	EVP_CIPHER_CTX_free( ctx );
	cLen += oLen;
	
	delete message;
	
	return new NetMessage( (char*)cTxt , cLen );
	
}

Message* cipherAES::decryptMessage( NetMessage message ){

	int pLen, oLen = 0;

	if( key == NULL || message.getMessage() == NULL || message.length() < 1 ){
		cout<<"[cipherAES] Error during the encryption of the message"<<endl;
		return NULL;
	}
	
	unsigned char* pTxt = (unsigned char*)malloc( message.length() );
	
	if( pTxt == NULL ) 
		return NULL;
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit( ctx, EVP_aes_256_cbc(), key , NULL );
	EVP_DecryptUpdate( ctx , pTxt , &oLen, (unsigned char*)message.getMessage() , message.length() );
	pLen = oLen;
	EVP_DecryptFinal( ctx , pTxt + pLen , &oLen );
	EVP_CIPHER_CTX_free( ctx );
	pLen += oLen;
	
	return new Message((char*) pTxt , pLen );
	
}

int main(){
	
	cipherAES* aes = new cipherAES( "password" );
	Message* msg = new Message(MessageType::LOGIN_OK);

	NetMessage* cMsg = aes->encryptMessage( *msg );
	cout<<cMsg->getMessage()<<endl;
	msg = aes->decryptMessage( *cMsg );
	switch(msg->getType()){
		case 0:
			cout<<"ACK"<<endl;
			break;
		case 1:
			cout<<"SIGN_UP"<<endl;
			break;
		case 2:
			cout<<"LOGIN"<<endl;
			break;
		case 3:
			cout<<"LOGIN_OK"<<endl;
			break;
		case 4:
			cout<<"LOGIN_FAIL"<<endl;
			break;
		default: 
			cout<<"MessageType not defined"<<endl;
	}

	return 0;
	
}
#include "CipherRSA.h"
#include "CipherDH.h"
#include "CipherAES.h"
#include "../Logger.h"
#include "../utility/Message.h"
#include "../utility/NetMessage.h"
using namespace utility; 

namespace cipher
{
  class CipherClient
  {
    private:
      EVP_PKEY* serverKey=nullptr;
      bool RSA_is_start=false;
      CipherRSA* rsa;
      CipherDH*  dh;
      CipherAES* aes;
    public:
      CipherClient(string username,string password);
      CipherClient();
      ~CipherClient();
      void newRSAParameter(string username,string password);
      bool toSecureForm( Message* message, SessionKey* aesKey );
      bool fromSecureForm( Message* message , string username , SessionKey* aesKey,bool serverKeyExchange);
      bool getRSA_is_start();
      //NetMessage* getServerCertificate();//da verificare utilita
      SessionKey* getSessionKey( unsigned char* param, unsigned int len );
      NetMessage* getPartialKey();
  };







}

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
      CipherRSA* rsa;
      CipherDH*  dh;
      CipherAES* aes;
    public:
      CipherClient(string username,string password);
      ~CipherClient();
      bool toSecureForm( Message* message, SessionKey* aesKey );
      bool fromSecureForm( Message* message , string username , SessionKey* aesKey );
      //NetMessage* getServerCertificate();//da verificare utilita
      SessionKey* getSessionKey( unsigned char* param, unsigned int len );
      NetMessage* getPartialKey();
  };







}

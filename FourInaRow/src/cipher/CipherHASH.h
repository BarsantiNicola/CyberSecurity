#include<openssl/evp.h>
#include<openssl/conf.h>
#include<openssl/hmac.h>
#include<openssl/engine.h>
//#include "../Logger.h"
using namespace std;
namespace cipher
{
  class CipherHASH
  { 
      
    public:
      static unsigned char* hashFunction(unsigned char*,int);
      static unsigned char* hashFunction(unsigned char*,int,unsigned char*,int);
      static int hashLength();

  };





}

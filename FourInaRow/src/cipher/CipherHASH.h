#include<openssl/evp.h>
#include<openssl/conf.h>
#include<openssl/hmac.h>
using namespace std;
namespace cipher
{
  class CipherHASH
  {
    public:
      unsigned char* hashFunction(unsigned char*);
      unsigned char* hashFunction(unsigned char*,unsigned char*);

  };





}

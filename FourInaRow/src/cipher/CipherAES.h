#include<string>
#include<stdio.h>
#include<string.h>
#include<limits.h>
#include<string.h>
#include<openssl/evp.h>
#include<openssl/pem.h>
#include<openssl/rand.h>
#include<stdlib.h>
#include<time.h>
#include"../Logger"
#include "../utility/NetMessage.h"
#include "../utility/Message.h"
using namespace std;
namespace cipher
{
  class CipherAES{
  private:
    unsigned char* iv;
    int ivLength;
    unsigned char* key;
    int keyLen;
  public:
    CipherAES();
    CipherAES(SessionKey*);
    bool modifyParam(SessionKey*);
    Message* encryptMessage(Message*);
    Message* decryptMessage(Message*);
  private:
    unsigned char* fromIntToUnsignedChar(int,int*);
    int gcmEncrypt(unsigned char*,int,unsigned char*,unsigned char*,unsigned char*);
    int gcmDecrypt(unsigned char*,int,unsigned char*,int,unsigned char*,unsigned char*);
  };




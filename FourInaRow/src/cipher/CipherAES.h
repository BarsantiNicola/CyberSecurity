
#ifndef FOURINAROW_CIPHERAES_H
#define FOURINAROW_CIPHERAES_H

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
#include"../Logger.h"
#include"CipherDH.h"
#include "../utility/NetMessage.h"
#include "../utility/Message.h"
using namespace utility;
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
    CipherAES(struct SessionKey*);
    bool modifyParam(struct SessionKey*);
    Message* encryptMessage(Message);
    Message* decryptMessage(Message);
    ~CipherAES();
  private:
    unsigned char* fromIntToUnsignedChar(int,int*);
    int gcmEncrypt(unsigned char*,int,unsigned char*,int,unsigned char*,unsigned char*);
    int gcmDecrypt(unsigned char*,int,unsigned char*,int,unsigned char*,unsigned char*);
    bool copyToFrom(int,int,unsigned char*,unsigned char*);
    bool insertField(MessageType,Message*,unsigned char*,int);
  };

}

#endif //FOURINAROW_CIPHERAES-H

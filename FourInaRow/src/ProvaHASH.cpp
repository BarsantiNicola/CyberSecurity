#include<iostream>
#include"cipher/CipherHASH.h"
//#include "Logger.h"
using namespace cipher;
int main()
{
  //Logger::setThreshold( VERY_VERBOSE );
  unsigned char msg[]="Questo messaggio serve per provare la correttezza della funzione di hashing, provando a vedere con un messaggio di medie dimensioni come questo.?";
  unsigned char key_hmac[]="0123456789012345678901234567890";
  size_t key_hmac_size=sizeof(key_hmac);

  int len=sizeof(msg);
  CipherHASH c;
  unsigned char* hash=CipherHASH::hashFunction(msg,len); 
  unsigned char* hash2=CipherHASH::hashFunction(msg,len,key_hmac,key_hmac_size);
  for(int i=0;i<CipherHASH::hashLength();++i)
  {
   printf("%02x",(unsigned char)hash[i]);
  }
   printf("\n");
  for(int i=0;i<CipherHASH::hashLength();++i)
  {
   printf("%02x",(unsigned char)hash2[i]);
  }
   printf("\n");
}

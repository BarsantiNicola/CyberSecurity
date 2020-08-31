#include<iostream>
#include "Logger.h"
#include "utility/NetMessage.h"
#include "utility/Message.h"
#include "cipher/CipherAES.h"
#include"cipher/CipherDH.h"
using namespace cipher;

int main()
{
  Logger::setThreshold( VERY_VERBOSE );
  unsigned char k[]="01234567890123456789012345678901";
  unsigned char iv[]="0000000000000001";
  unsigned char rl[]="prova";
  std::cout<<"lunghezza campo:"<<sizeof(rl)<<endl;
  int keyLen=32;
  std::cout<<"prova in esadecimale:"<<'\n';
  BIO_dump_fp(stdout,(const char*)rl,sizeof(rl));
  utility::Message mess;
  utility::Message *resMess;
  utility::Message *messCiph;
  int ivLength=16;
  struct SessionKey sk;
  sk.sessionKey=k;
  sk.sessionKeyLen=keyLen;
  sk.iv=iv;
  sk.ivLen=ivLength;
  CipherAES cAES(&sk);
  mess.setMessageType(RANK_LIST);
  mess.setNonce(12);
  std::cout<<"valore nonce:"<<mess.getNonce()<<endl;
  mess.setRankList( rl, sizeof(rl) );
  messCiph=cAES.encryptMessage(mess);
  /*DEBUG ELIMINARE PIÙ TARDI*/
  //vverbose<<"-->[Prova][main] the value of ciphertxt"<<'\n';
  //BIO_dump_fp(stdout,(const char*)messCiph->getRankList(),messCiph->getRankListLen());
    
    /*--FINE DEBUG*/
  if(messCiph==nullptr)
  {
    std::cout<<"someError"<<endl;
  }
  else
  {
   std::cout<<"for now ok"<<endl;
  }
  
  resMess=cAES.decryptMessage(*messCiph);
  if(resMess==nullptr)
  {
    std::cout<<"someError"<<endl;
  }
  else
  {
   std::cout<<"for now ok"<<endl;
   std::cout<<resMess->getNonce()<<endl;
  }
  return 0;
  
  
  
}


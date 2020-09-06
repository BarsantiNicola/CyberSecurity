#include"CipherClient.h"
namespace cipher
{
  CipherClient::CipherClient(string username,string password)
  {
    this->rsa = new CipherRSA(username, password, false );
    this->dh  = new CipherDH();
    this->aes = new CipherAES();
    if( !this->rsa || !this->dh || !this->aes )
    {
      verbose<<"-->[CipherClient][Costructor] Fatal error, unable to load cipher suites"<<'\n';
      exit(1);
    }
  }
   CipherClient::~CipherClient()
   {
     delete this->rsa;
     delete this->dh;
     delete this->aes;
   }




}

#include"CipherHASH.h"
namespace cipher
{
  //this function create and return an HASH of an message without a key return  nullptr in case of error
  unsigned char* CipherHASH::hashFunction(unsigned char* message,int message_length)
  {
    if(message_length<=0||message==nullptr)
      return nullptr;
    unsigned char* hash_buf;
    unsigned int hash_size;
    const EVP_MD* md=EVP_sha256();
    EVP_MD_CTX* mdctx;
    hash_size=EVP_MD_size(md);
    hash_buf=(unsigned char*)malloc(hash_size);
    if(!hash_buf)
    {
      return nullptr;
    }
    mdctx= EVP_MD_CTX_new();
    if(!mdctx)
    {
      return nullptr;
    }
    EVP_DigestInit(mdctx,md);
    EVP_DigestUpdate(mdctx,(unsigned char*)message,message_length);
    EVP_DigestFinal(mdctx,hash_buf,&hash_size);
    EVP_MD_CTX_free(mdctx);
    return hash_buf;
  }
  //this function create an HASH of an message with a key return nullptr in case of failure
  unsigned char* CipherHASH::hashFunction(unsigned char* message,int message_length,unsigned char* key_hmac,int key_length)
  {
    if(key_length<=0 ||message_length<=0||message==nullptr)
      return nullptr;
    unsigned char* hash_buf;
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
    int hash_size;
    size_t key_hmac_size = key_length;
    const EVP_MD* md=EVP_sha256();
    HMAC_CTX* mdctx;
    hash_size=EVP_MD_size(md);
    hash_buf=(unsigned char*)malloc(hash_size);
    if(!hash_buf)
    {
      return nullptr;
    }
    mdctx= HMAC_CTX_new();
    if(!mdctx)
    {
      return nullptr;
    }
    HMAC_Init_ex(mdctx,key_hmac,key_hmac_size,md,nullptr);
    HMAC_Update(mdctx,message,message_length);
    HMAC_Final(mdctx,hash_buf,(unsigned int*)&hash_size);
    HMAC_CTX_free(mdctx);
    return hash_buf;
  }
  //return the length of an hashLength
  int CipherHASH::hashLength()
  {
    return EVP_MD_size(EVP_sha256());
  }
}

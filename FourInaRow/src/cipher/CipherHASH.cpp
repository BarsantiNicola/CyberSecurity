#include"CipherHASH"
namespace cipher
{
  unsigned char* CipherHASH::hashFunction(unsigned char* message,int message_length)
  {
    if(message_length<=0)
      return NULL;
    unsigned char* hash_buf;
    int hash_size;
    const EVP_MD* md=EVP_sha256();
    EVP_MD_CTX* mdctx;
    hash_size=EVP_MD_size(md);
    hash_buf=(unsigned char*)malloc(hash_size);
    if(!hash_buf)
    {
      return NULL;
    }
    mdctx= HMAC_CTX_new();
    if(!mdctx)
    {
      return NULL;
    }
    EVP_DigestInit(mdctx,md);
    EVP_DigestUpdate(mdctx,(unsigned char*)message,message_length);
    EVP_DigestFinal(mdctx,hash_buf,&hash_size);
    EVP_MD_CTX_free(mdctx);
    return hash_buf;
  }
  unsigned char* CipherHASH::hashFunction(unsigned char* message,int message_length,unsigned char* key_hmac,int key_length)
  {
    if(key_length<=0 ||message_length<=0)
      return NULL;
    unsigned char* hash_buf;
    int hash_size;
    size_t key_hmac_size = key_length);
    const EVP_MD* md=EVP_sha256();
    EVP_MD_CTX* mdctx;
    hash_size=EVP_MD_size(md);
    hash_buf=(unsigned char*)malloc(hash_size);
    if(!hash_buf)
    {
      return NULL;
    }
    mdctx= HMAC_CTX_new();
    if(!mdctx)
    {
      return NULL;
    }
    HMAC_Init(mdctx,key_hmac,key_hmac_size,md);
    HMAC_Update(mdctx,message,message_length);
    HMAC_Final(mdctx,hash_buf,(unsigned int*)&hash_size);
    HMAC_CTX_free(mdctx);
    return hash_buf;
  }
  int CipherHASH::hashLength()
  {
    return EVP_MD_size(EVP_sha256());
  }
}

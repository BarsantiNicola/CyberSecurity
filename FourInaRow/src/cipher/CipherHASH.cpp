#include"CipherHASH"
namespace cipher
{
  unsigned char* CipherHASH::hashFunction(unsigned char* message)
  {
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
    EVP_DigestUpdate(mdctx,(unsigned char*)message,sizeof(message));
    EVP_DigestFinal(mdctx,hash_buf,&hash_size);
    EVP_MD_CTX_free(mdctx);
    return hash_buf;
  }
  unsigned char* CipherHASH::hashFunction(unsigned char* message,unsigned char* key_hmac)
  {
    unsigned char* hash_buf;
    int hash_size;
    size_t key_hmac_size = sizeof(key_hamac);
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
    HMAC_Update(mdctx,message,sizeof(message));
    HMAC_Final(mdctx,hash_buf,(unsigned int*)&hash_size);
    HMAC_CTX_free(mdctx);
    return hash_buf;
  }
}

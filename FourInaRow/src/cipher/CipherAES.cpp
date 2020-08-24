#include"CipherAES.h"
namespace cipher
{

  CipherAES::CipherAES(SessionKey* session_key)
  {
    this->iv=session_key->iv;
    this->ivLength=session_key->ivLen;
    this->key=session_key->sessionKey;
    this->key=session_key->sessionKeyLength;
  }

  bool CipherAES::modifyParam(SessionKey* session_key)
  {
    if(session_key==NULL)
    {
      return false;
    }
    this->iv=session_key->iv;
    this->ivLength=session_key->ivLen;
    this->key=session_key->sessionKey;
    this->key=session_key->sessionKeyLength;
    return true;
  }
/*
--------------------------function gcmDecrypt------------------------------
This functio is used for Encrypt a message and return the lengrh of ciphertext if there is an
error return -1 value
*/
  int CipherAES::gcmEncrypt(unsigned char*plaintext,int plaintextLen,unsigned char*aad,int aadLen,unsigned char*ciphertext,unsigned char*tag)
  {
    EVP_CIPHER_CTX ctx*;
    int len;
    int ciphertextLen;
    if(!(ctx=EVP_CIPHER_CTX_new()))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error on allocate space for context"<<'\n';
      return -1;
    }
    if(1!=EVP_EncryptInit(ctx,EVP_aes_256_gcm(),key,iv))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error in the initialise the encryption operation"<<'\n';
      return -1;
    }
    if(1!=EVP_EncryptUpdate(ctx,NULL,&len,aad,aadLen))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error to provide AAD data"<<'\n';
      return -1;
    }
    if(1!=EVP_EncryptUpdate(ctx,ciphertext,&len,plaintext,plaintextLen))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error to encrypt message"<<'\n';
      return -1;
    }
    ciphertextLen=len;
    if(1!=EVP_EncryptFinal(ctx,ciphertext+len,&len))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error to finalize the encryption"<<'\n';
      return -1;
    }
    ciphertextLen+=len;
    if(1!=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AED_GET_TAG,16,tag))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error to get the tag"<'\n';
      return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ciphertextLen;
}
/*
--------------------------function gcmDecrypt------------------------------
This functio is used for decrypt a message and return the length of ciphertext and
verify the tag if there is an error return -1 value and -2 if the verify fails 
*/

  int CipherAES::gcmDecrypt(unsigned char *ciphertext,int ciphertextLen,unsigned char *aad,int aadLen,unsigned char* tag,unsigned char*plaintext)
  {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintextLen;
    int ret;
    if(!(ctx=EVP_CIPHER_CTX_new()))
    {
      verbose<<"-->[CipherAES][gcmDecrypt] error on allocate space for context"<<'\n';
      return -1;
    }
    if(!EVP_DecryptInit(ctx,EVP_aes_256_gcm(),key,iv))
    {
      verbose<<"-->[CipherAES][gcmDecrypt] error in the initialise the decryption operation"<<'\n';
      return -1;
    }
    if(!EVP_DecryptUpdate(ctx,NULL,&len,aad,aadLen))
    {
      verbose<<"-->[CipherAES][gcmDecrypt] error to provide AAD data"<<'\n';
      return -1;
    }
    if(!EVP_DecryptUpdate(ctx,plaintext,&len,ciphertext,ciphertextLen))
    {
      verbose<<"-->[CipherAES][gcmDecrypt] error to decrypt message"<<'\n';
      return -1;
    }
    plaintextLen=len;
    if(!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AED_SET_TAG,16,tag))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error to get the tag"<'\n';
      return -1;
    }
    ret= EVP_DecryptFinal(ctx,plaintext + len, &len);
    EVP_CIPHER_CTX_cleanup(ctx);
    
    if(ret>0)
    {
      plaintextLen+=len;
      return plaintextLen;
    }
    else
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error Verify failed"<'\n';
      return -2;
    }
  }
  Message* CipherAES::encryptMessage(Message* message)
  {
    NetMessa
  }

}


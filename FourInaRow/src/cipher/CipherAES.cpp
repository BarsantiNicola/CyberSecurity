#include"CipherAES.h"
namespace cipher
{
  CipherAES::CipherAES()
  {
    vverbose<<"-->[CipherAES][Costruct] object create succesfully"<<'\n';

  }
  CipherAES::CipherAES(SessionKey* session_key)
  {
    if(session_key==nullptr)
    {
      verbose<<"-->[CipherAES][Costruct] error to create the object"<<'\n';
      exit(1);
    }
    if(session_key->iv==nullptr)
    {
      verbose<<"-->[CipherAES][Costruct] error to create the object iv is null"<<'\n';
      exit(1);
    }
    if(session_key->sessionKey==nullptr)
    {
      verbose<<"-->[CipherAES][Costruct] error to create the object sessionkey is null"<<'\n';
      exit(1);
    }
    this->iv=session_key->iv;
    this->ivLength=session_key->ivLen;
    this->key=session_key->sessionKey;
    this->keyLen=session_key->sessionKeyLen;
  }

  bool CipherAES::modifyParam(SessionKey* session_key)
  {
    if(session_key==nullptr)
    {
      return false;
    }
    if(session_key->iv==nullptr)
    {
      verbose<<"-->[CipherAES][Costruct] error to create the object iv is null"<<'\n';
      return false;
    }
    if(session_key->sessionKey==nullptr)
    {
      verbose<<"-->[CipherAES][Costruct] error to create the object sessionkey is null"<<'\n';
      return false;
    }
    this->iv=session_key->iv;
    this->ivLength=session_key->ivLen;
    this->key=session_key->sessionKey;
    this->keyLen=session_key->sessionKeyLen;
    return true;
  }
/*
--------------------------function gcmDecrypt------------------------------
This functio is used for Encrypt a message and return the lengrh of ciphertext if there is an
error return -1 value
*/
  int CipherAES::gcmEncrypt(unsigned char*plaintext,int plaintextLen,unsigned char*aad,int aadLen,unsigned char*ciphertext,unsigned char*tag)
  {
    EVP_CIPHER_CTX *ctx;
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
    if(1!=EVP_EncryptUpdate(ctx,nullptr,&len,aad,aadLen))
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
    if(1!=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,16,tag))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error to get the tag"<<'\n';
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
    if(!EVP_DecryptUpdate(ctx,nullptr,&len,aad,aadLen))
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
    if(!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG,16,tag))
    {
      verbose<<"-->[CipherAES][gcmEncrypt] error to get the tag"<<'\n';
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
      verbose<<"-->[CipherAES][gcmEncrypt] error Verify failed"<<'\n';
      return -2;
    }
  }
/*
--------------------------------function encriptMessage()----------------------------
This function encryptMessage with AES_256 gcm
*/
  Message* CipherAES::encryptMessage(Message message)
  {
    int lengthPlaintext=0;
    int lengthToCipher=0;
    int ciphertextLength;
    unsigned char* ciphertext;
    unsigned char* tag;
    Converter converter;
    NetMessage* netMessage=converter.compactForm( message.getMessageType(),message,&lengthPlaintext );
    
    if(netMessage==nullptr)
    {
       verbose<<"-->[CipherAES][encryptMessage] errorTo create a message compact"<<'\n';
       return nullptr;
    }
    lengthToCipher=netMessage->length()-lengthPlaintext;
    if(lengthToCipher==0)
    {
      unsigned char app[]="";
      int ret=gcmEncrypt(app,0,netMessage->getMessage(),lengthPlaintext,ciphertext,tag);
      if(ret==-1)
      {
        return nullptr;
      }
      Message *newMessage=new Message(message );
      newMessage->setSignature( tag , 16 );
      return newMessage;
    }
    else
    {
      unsigned char* textToCipher=new unsigned char[lengthToCipher];
      unsigned char* textInPlain=new unsigned char[lengthPlaintext];
      bool res= copyToFrom(0,lengthPlaintext,netMessage->getMessage(),textInPlain);
      if (res==false)
      {
       verbose<<"-->[CipherAES][encryptMessage] errorTo copy a message"<<'\n';
       return nullptr;
      }
      res=copyToFrom(lengthPlaintext,netMessage->length(),netMessage->getMessage(),textToCipher);
      if (res==false)
      {
       verbose<<"-->[CipherAES][encryptMessage] errorTo copy a message"<<'\n';
       return nullptr;
      }
      int lengthcipher=gcmEncrypt(textToCipher,lengthToCipher,textInPlain,lengthPlaintext,ciphertext,tag);
      if(lengthcipher==-1)
        return nullptr;
      Message *newMessage=new Message(message );
      newMessage->setSignature( tag , 16 );

      bool result=insertField(newMessage->getMessageType(),newMessage,ciphertext,lengthcipher);
      if(result==false)
        return nullptr;

      return newMessage;
    }
  }
/*--------------------Function decryptMessage--------------------------------------*/
  Message* CipherAES::decryptMessage(Message message)
 {
    int lengthCleareText=0;
    int lengthToDecrypt=0;
    int ciphertextLength;
    unsigned char* plaintext;
    unsigned char* tag;
    Converter converter;
    
    NetMessage* netMessage=converter.compactForm( message.getMessageType(),message,&lengthCleareText );
    
    if(netMessage==nullptr)
    {
       verbose<<"-->[CipherAES][dencryptMessage] errorTo create a message compact"<<'\n';
       return nullptr;
    }
    lengthToDecrypt=netMessage->length()-lengthCleareText;
    if(lengthToDecrypt==0)
    {
      Message *newMessage=new Message(message );
      tag=newMessage->getSignature();
      unsigned char app[]="";
      int res=gcmDecrypt(app,0,netMessage->getMessage(),lengthCleareText,tag,plaintext);
      if(res==-2)
      {
        verbose<<"-->[CipherAES][dencryptMessage] error message not valid"<<'\n';
        return nullptr;
      }
      if(res==-1)
      {
        verbose<<"-->[CipherAES][dencryptMessage] error to decrypt the message"<<'\n';
        return nullptr;
      }
      
      
      return newMessage;
    }
    else
    {
      unsigned char* textToDecrypt=new unsigned char[lengthToDecrypt];
      unsigned char* textInPlain=new unsigned char[lengthCleareText];
      bool res= copyToFrom(0,lengthCleareText,netMessage->getMessage(),textInPlain);
      if (res==false)
      {
       verbose<<"-->[CipherAES][dencryptMessage] errorTo copy a message"<<'\n';
       return nullptr;
      }
      res=copyToFrom(lengthCleareText,netMessage->length(),netMessage->getMessage(),textToDecrypt);
      if (res==false)
      {
       verbose<<"-->[CipherAES][dencryptMessage] errorTo copy a message"<<'\n';
       return nullptr;
      }      
      Message *newMessage=new Message(message );
      tag=newMessage->getSignature();
      int lengthplain=gcmDecrypt(textToDecrypt,lengthToDecrypt,textInPlain,lengthCleareText,plaintext,tag);
      if(res==-2)
      {
        verbose<<"-->[CipherAES][dencryptMessage] error message not valid"<<'\n';
        return nullptr;
      }
      if(res==-1)
      {
        verbose<<"-->[CipherAES][dencryptMessage] error to decrypt the message"<<'\n';
        return nullptr;
      }
            bool result=insertField(newMessage->getMessageType(),newMessage,plaintext,lengthplain);
      if(result==false)
        return nullptr;

      return newMessage;
    }
 }
/*
---------------------------------function CipherAES()-------------------------------
*/
  bool CipherAES::copyToFrom(int start,int end,unsigned char* originalArray,unsigned char* copyArray)
  {
    if(start>end||start<0||end<0)
      return false;
    for(int i=start;i<end;i++)
    {
      copyArray[i]=originalArray[i];
    } 
    return true;
  } 
 

 bool CipherAES::insertField(MessageType type,Message* message,unsigned char* valueField,int valueFieldLength)
 {
   bool result=false;
   switch(type)
   {
    case USER_LIST:
      message->setUserList(valueField,valueFieldLength);
      result=true;
      break;
    
    case RANK_LIST:
      message->setRankList(valueField,valueFieldLength);
      result=true;
      break;
   
    case GAME_PARAM:
      message->setNetInformations( valueField , valueFieldLength );
      result=true;
      break;

    case MOVE:
      message->setChosenColumn(valueField,valueFieldLength);
      break;

    case CHAT:
      message->setMessage(valueField,valueFieldLength);
      result=true;
      break;

    default:
      result=false;
      break;
   }
   return result;
 }
 ~CipherAES::CipherAES()
 {
   vverbose<<"destruct the object"<<n;
   delete[] iv;
   delete[] key;
 }
}
 

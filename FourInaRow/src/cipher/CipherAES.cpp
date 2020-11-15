#include"CipherAES.h"
namespace cipher
{
  CipherAES::CipherAES()
  {
    vverbose<<"-->[CipherAES][Costruct] object create succesfully"<<'\n';

  }
  CipherAES::CipherAES(struct SessionKey* session_key)
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

  bool CipherAES::modifyParam(struct SessionKey* session_key)
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
--------------------------function gcmEncrypt------------------------------
This functio is used for Encrypt a message and return the lengrh of ciphertext if there is an
error return -1 value
*/
  int CipherAES::gcmEncrypt(unsigned char*plaintext,int plaintextLen,unsigned char*aad,int aadLen,unsigned char*ciphertext,unsigned char*tag)
  {
    if(plaintext==nullptr)
    {
      verbose<<"-->[CipherAES][gcmEncrypt] plaintext is null pointer"<<'\n';
      return -1;
    }
    if(aad==nullptr)
    {
      verbose<<"-->[CipherAES][gcmEncrypt] aad is null pointer"<<'\n';
      return -1;
    }

    if(tag==nullptr)
    {
      verbose<<"-->[CipherAES][gcmEncrypt] tag is null pointer"<<'\n';
      return -1;
    }    
    if(ciphertext==nullptr)
    {
      verbose<<"-->[CipherAES][gcmEncrypt] ciphertext is null pointer"<<'\n';
      return -1;
    }
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
    vverbose<<"-->[CipherAES][gcmEncrypt] message encrypt correctly"<<'\n';
    return ciphertextLen;
}
/*
--------------------------function gcmDecrypt------------------------------
This functio is used for decrypt a message and return the length of ciphertext and
verify the tag if there is an error return -1 value and -2 if the verify fails 
*/

  int CipherAES::gcmDecrypt(unsigned char *ciphertext,int ciphertextLen,unsigned char *aad,int aadLen,unsigned char* tag,unsigned char*plaintext)
  {
    if(plaintext==nullptr)
    {
      verbose<<"-->[CipherAES][gcmDecrypt] plaintext is null pointer"<<'\n';
      return -1;
    }
    if(aad==nullptr)
    {
      verbose<<"-->[CipherAES][gcmDecrypt] aad is null pointer"<<'\n';
      return -1;
    }
    if(ciphertext==nullptr)
    {
      verbose<<"-->[CipherAES][gcmDecrypt] ciphertext is null pointer"<<'\n';
      return -1;
    }
    if(tag==nullptr)
    {
      verbose<<"-->[CipherAES][gcmDecrypt] tag is null pointer"<<'\n';
      return -1;
    }

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
      verbose<<"-->[CipherAES][gcmDecrypt] error to get the tag"<<'\n';
      return -1;
    }
    ret= EVP_DecryptFinal(ctx,plaintext + len, &len);
    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret>0)
    {
      plaintextLen+=len;
      vverbose<<"-->[CipherAES][gcmDecrypt] message decrypt correctly"<<'\n';
      return plaintextLen;
    }
    else
    {
      verbose<<"-->[CipherAES][gcmDecrypt] error Verify failed"<<'\n';
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
    try
    {
      tag=new unsigned char[16];
    }
    catch(std::bad_alloc& e)
    {
      return nullptr;
    }
    Converter converter;
    NetMessage* netMessage=converter.compactForm( message.getMessageType(),message,&lengthPlaintext );
    if(iv==nullptr || key==nullptr)
    {
       verbose<<"-->[CipherAES][encryptMessage] error key or iv is nullptr"<<'\n';
       delete[]tag;
       return nullptr;
    } 
    //vverbose<<"-->[CipherAES][encryptMessage] key and iv is nullptr"<<'\n';
    if(netMessage==nullptr)
    {
       verbose<<"-->[CipherAES][encryptMessage] errorTo create a message compact"<<'\n';
       delete[]tag;
       return nullptr;
    }
    vverbose<<"-->[CipherAES][encryptMessage] message compact created succesfully"<<'\n';
    lengthToCipher=netMessage->length()-lengthPlaintext;
    vverbose<<"-->[CipherAES][encryptMessage] length to cipher:"<<lengthToCipher<<'\n';
    if(lengthToCipher==0)
    {
      unsigned char app[]="";
      try
      {
        ciphertext=new unsigned char[0];
        
      }   
      catch(std::bad_alloc& e)
      {
        delete[]tag;
        return nullptr;
      }

      int ret=gcmEncrypt(app,0,netMessage->getMessage(),lengthPlaintext,ciphertext,tag);
      if(ret==-1)
      {
        delete[]tag;
        return nullptr;
      }
      Message *newMessage=new Message(message );

      newMessage->setSignature( tag , 16 );
      //delete[]tag;
      return newMessage;
    }
    else
    {
      unsigned char* textToCipher;
      unsigned char* textInPlain;
      try
      {
        textToCipher=new unsigned char[lengthToCipher];
        textInPlain=new unsigned char[lengthPlaintext];
      }
      catch(std::bad_alloc& e)
      {
        verbose<<"-->[CipherAES][encryptMessage] error bad alloc exception"<<'\n';
        return nullptr;
      }
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
       delete[]tag;
       return nullptr;
      }
      try
      {
        ciphertext=new unsigned char[lengthToCipher];
      }
      catch(std::bad_alloc& e)
      {
        verbose<<"-->[CipherAES][encryptMessage] error bad alloc exception ciphertext"<<'\n';
        delete[]tag;
        return nullptr;
      }
      int lengthcipher=gcmEncrypt(textToCipher,lengthToCipher,textInPlain,lengthPlaintext,ciphertext,tag);
      
      if(lengthcipher==-1)
      {
        verbose<<"-->[CipherAES][encryptMessage] error lengthcipher -1"<<'\n';
        delete[]ciphertext;
        delete[]tag;
        return nullptr;
      }
      vverbose<<"-->[CipherAES][encryptMessage] cipher message created succesfully cipherLength: "<<lengthcipher<<'\n';

      Message *newMessage;
      try
      {
        newMessage=new Message(message);
      }
      catch(std::bad_alloc& e)
      {
        verbose<<"-->[CipherAES][encryptMessage] error bad alloc exception newMessage"<<'\n';
        delete[]ciphertext;
        delete[]tag;
        return nullptr;
      }
      if(newMessage->getMessageType()==GAME)
      {
        newMessage->setSignatureAES( tag , 16 );
      }
      else
      {
        newMessage->setSignature( tag , 16 );
      }

      bool result=insertField(newMessage->getMessageType(),newMessage,ciphertext,lengthcipher,false);
      if(result==false)
      {
        verbose<<"-->[CipherAES][encryptMessage] error insert field"<<'\n';
        delete[]ciphertext;
        delete[]tag;
        return nullptr;
      }
      delete[]ciphertext;
      //delete[]tag;
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
    try
    {
      tag=new unsigned char[16];
    }
    catch(std::bad_alloc& e)
    {
      return nullptr;
    }
    Converter converter;

    NetMessage* netMessage=converter.compactForm( message.getMessageType(),message,&lengthCleareText );
    if(iv==nullptr || key==nullptr)
    {
       verbose<<"-->[CipherAES][decryptMessage] error key or iv is nullptr"<<'\n';
       return nullptr;
    }
    if(netMessage==nullptr)
    {
       verbose<<"-->[CipherAES][decryptMessage] errorTo create a message compact"<<'\n';
       return nullptr;
    }

    lengthToDecrypt=netMessage->length()-lengthCleareText;
    if(lengthToDecrypt==0)
    {
      Message *newMessage;
      try
      {
        newMessage=new Message(message );
        plaintext=new unsigned char[0];
      }
      catch(std::bad_alloc& e)
      {
        return nullptr;
      }
      tag=newMessage->getSignature();
      unsigned char app[]="";
      try
      {
        plaintext=new unsigned char[0];
      }
      catch(std::bad_alloc& e)
      {
        delete[]tag;
        return nullptr;
      }
      int res=gcmDecrypt(app,0,netMessage->getMessage(),lengthCleareText,tag,plaintext);
      if(res==-2)
      {
        delete[]tag;
        verbose<<"-->[CipherAES][decryptMessage] error message not valid"<<'\n';
        return nullptr;
      }
      if(res==-1)
      {
        delete[]tag;
        verbose<<"-->[CipherAES][decryptMessage] error to decrypt the message"<<'\n';
        return nullptr;
      }
      
      delete[]tag;
      return newMessage;
    }
    else
    {
      vverbose<<"-->[CipherAES][decryptMessage] length to decrypt: "<<lengthToDecrypt<<'\n';
      unsigned char* textToDecrypt;
      unsigned char* textInPlain;
      try
      {
        textToDecrypt=new unsigned char[lengthToDecrypt];
        textInPlain=new unsigned char[lengthCleareText];
      }
      catch(std::bad_alloc& e)
      {
        delete[]tag;
        return nullptr;
      }
      bool res= copyToFrom(0,lengthCleareText,netMessage->getMessage(),textInPlain);
      if (res==false)
      {
       verbose<<"-->[CipherAES][dencryptMessage] errorTo copy a message"<<'\n';
       delete[]textToDecrypt;
       delete[]textInPlain;
       delete[]tag;
       return nullptr;
      }
      res=copyToFrom(lengthCleareText,netMessage->length(),netMessage->getMessage(),textToDecrypt);
      if (res==false)
      {
       verbose<<"-->[CipherAES][dencryptMessage] errorTo copy a message"<<'\n';
       delete[]textToDecrypt;
       delete[]textInPlain;
       delete[]tag;
       return nullptr;
      }      
      Message *newMessage;
      try
      {      
        newMessage=new Message(message );
      }
      catch(std::bad_alloc& e)
      {
        delete[]textToDecrypt;
        delete[]textInPlain;
        delete[]tag;
        return nullptr;
      }
      if(newMessage->getMessageType()==GAME)
      {
        tag=newMessage->getSignatureAES();
      }
      else
      {
        tag=newMessage->getSignature();
      }

      try
      {
        plaintext=new unsigned char[lengthToDecrypt];
      }
      catch(std::bad_alloc& e)
      {
        delete[]textToDecrypt;
        delete[]textInPlain;
        delete newMessage;
        delete[]tag;
        return nullptr;
      }
      int lengthplain=gcmDecrypt(textToDecrypt,lengthToDecrypt,textInPlain,lengthCleareText,tag,plaintext);
      if(lengthplain==-2)
      {
        verbose<<"-->[CipherAES][dencryptMessage] error message not valid"<<'\n';
        delete[]textToDecrypt;
        delete[]textInPlain;
        delete[]tag;
        delete[]plaintext;
        return nullptr;
      }
      if(lengthplain==-1)
      {
        verbose<<"-->[CipherAES][dencryptMessage] error to decrypt the message"<<'\n';
        delete[]textToDecrypt;
        delete[]textInPlain;
        delete[]tag;
        delete[]plaintext;
        return nullptr;
      }
            bool result=insertField(newMessage->getMessageType(),newMessage,plaintext,lengthplain,true);
      if(result==false)
      {
        delete[]textToDecrypt;
        delete[]textInPlain;
        delete[]tag;
        delete[]plaintext;
        return nullptr;
      }
      delete[]textToDecrypt;
      delete[]textInPlain;
      delete[]tag;
      delete[]plaintext;
      return newMessage;
    }
 }
/*
---------------------------------function CipherAES()-------------------------------
*/
  bool CipherAES::copyToFrom(int start,int end,unsigned char* originalArray,unsigned char* copyArray)
  {
    int j=0;
    if(start>end||start<0||end<0)
      return false;
    for(int i=start;i<end;i++)
    {
      copyArray[j]=originalArray[i];
      ++j;
    } 
    return true;
  } 
 

 bool CipherAES::insertField(MessageType type,Message* message,unsigned char* valueField,int valueFieldLength,bool decrypt)
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
      if(decrypt)
      {
        unsigned int collSize;
        unsigned int gameSize;
        unsigned char* coll=nullptr;
        unsigned char* game=nullptr;
        result=getDeconcatenateLength(valueField,valueFieldLength,&collSize,&gameSize,(unsigned char) '&',(unsigned int) 5);
        if(!result)
        {
          vverbose<<"-->[CipherAES][insertField]error to obtain length"<<'\n';
          return false;
        }
        try
        {
          coll=new unsigned char[collSize];
        }
        catch(std::bad_alloc)
        {
          verbose<<"-->[CipherAES][insertField] bad alloc of coll";
          return false;
        }
        try
        {
          game=new unsigned char[gameSize];
        }
        catch(std::bad_alloc)
        {
          verbose<<"-->[CipherAES][insertField] bad alloc of game";
          delete coll;
          return false;
        }
        result=deconcatenateTwoField(valueField,valueFieldLength,coll,&collSize,game,&gameSize,(unsigned char) '&',(unsigned int) 5);
        if(!result)
        {
          vverbose<<"-->[CipherAES][Destructor]error to deconcatenate"<<'\n';
          return false;
        }
        message->setChosenColumn(coll,collSize);
        message->setMessage(game,gameSize);
        delete coll;
        delete game;
        result=true;
      }
      else
      {
        message->setChosenColumn(valueField,valueFieldLength);
        result=true;
      }
      break;
    case GAME:
       message->setChosenColumn(valueField,valueFieldLength);
       result=true;
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
 CipherAES::~CipherAES()
 {
   vverbose<<"-->[CipherAES][Destructor]destruct the object"<<'\n';
   /*delete[] iv;
   delete[] key;*/
 }
/*
  ------------------------------deconcatenateTwoField function----------------------------------
*/
  bool CipherAES::deconcatenateTwoField(unsigned char* originalField,unsigned int originalFieldSize,unsigned char* firstField,unsigned int* firstFieldSize,unsigned char* secondField,unsigned int* secondFieldSize, unsigned char separator,unsigned int numberSeparator)
  {
    int counter=0;
    int firstDimension=0;
    int secondDimension=0;
    if(originalField==nullptr||firstFieldSize==nullptr||secondFieldSize==nullptr||secondField==nullptr||firstField==nullptr)
      return false;
    for(int i=0;i<originalFieldSize;++i)
    {
       if(originalField[i]==separator)
       {
         ++counter;
         if(counter==numberSeparator)
         {
           firstDimension = (i-(numberSeparator-1));
           secondDimension= (originalFieldSize-i)-1;
           vverbose<<"-->[MainClient][deconcatenateTwoField]<<secondDimension:"<<secondDimension<<'\n';
           break;
         }
       }
       else
       {
         counter=0;
       }
    }
    if(firstDimension==0)
    {
      firstDimension=originalFieldSize;
    }

    
    for(int i=0;i<firstDimension;++i)
    {
      firstField[i]=originalField[i];  
         
    }
    
    vverbose<<"-->[MainClient][deconcatenateTwoField] "<<'\n';
    int j=0;
    for(int i=(firstDimension+numberSeparator);i<originalFieldSize;++i)
    {    
      secondField[j]=originalField[i];
      vverbose<<(char)secondField[j];
      ++j;
    }
    vverbose<<'\n';
    *firstFieldSize=firstDimension;
    *secondFieldSize=secondDimension;
    return true;
  }
/*
  ------------------------------getdeconcatenateLength function----------------------------------
*/
  bool CipherAES::getDeconcatenateLength(unsigned char* originalField,unsigned int originalFieldSize,unsigned int* firstFieldSize,unsigned int* secondFieldSize,unsigned char separator,unsigned int numberSeparator)
  {
    int counter=0;
    unsigned int firstDimension=0;
    unsigned int secondDimension=0;
    if(originalField==nullptr||firstFieldSize==nullptr||secondFieldSize==nullptr)
      return false;
    for(int i=0;i<originalFieldSize;++i)
    {
       if(originalField[i]==separator)
       {
         ++counter;
         if(counter==numberSeparator)
         {
           firstDimension = (i-(numberSeparator-1));
           secondDimension= (originalFieldSize-i)-1;
           vverbose<<"-->[CipherAES][deconcatenateTwoFieldLength]<<secondDimension:"<<secondDimension<<'\n';
           break;
         }
       }
       else
       {
         counter=0;
       }
    }
    if(firstDimension==0)
    {
      firstDimension=originalFieldSize;
    }
    *firstFieldSize=firstDimension;
    *secondFieldSize=secondDimension;
    return true;
  }
}
 

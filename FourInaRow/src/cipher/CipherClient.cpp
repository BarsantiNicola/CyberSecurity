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
/*------------------------------function toSecureForm------------------------------------*/
   bool CipherClient::toSecureForm( Message* message, SessionKey* aesKey )
   {
     if( message == nullptr )
     {
       verbose<<"-->[CipherClient][toSecureForm] Error, null pointer message"<<'\n';
       return false;
     }
     Message* app;
     switch( message->getMessageType())
     {
       case LOGIN_REQ:
         if( !this->rsa->sign(message))
           return false;
         break;
       case KEY_EXCHANGE:
         if( !this->rsa->sign(message))
           return false;
         break;
       
       case LOGOUT_REQ:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if( app == nullptr )
         {
           return false;
         }
         message->setSignature( app->getSignature(), app->getSignatureLen() );
         delete app;
         break;

       case USER_LIST_REQ:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if( app == nullptr )
         {
           return false;
         }
         message->setSignature( app->getSignature(), app->getSignatureLen() );
         delete app;
         break;
         
       case RANK_LIST_REQ:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if( app == nullptr )
         {
           return false;
         }
         message->setSignature(app->getSignature(), app->getSignatureLen());
         delete app;
         break;

       case MATCH:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if( app == nullptr )
         {
           return false;
         }
         message->setSignature(app->getSignature(), app->getSignatureLen());
         delete app;
         break;

       case ACCEPT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         delete app;
         break;

       case REJECT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         delete app;
         break;
   
      case WITHDRAW_REQ:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         delete app;
         break;  

      case MOVE:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         message->setChosenColumn(app->getChosenColumn(),app->getChosenColumnLength());
         delete app;
         break;

      case ACK:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         delete app;
         break; 
/*
      case ERROR:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         delete app;
         break; 
 */  
      case CHAT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         message->setMessage(app->getMessage(),app->getMessageLength());
         delete app;
         break;

      case DISCONNECT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         delete app;
         break;  

       case GAME:
         if(!aesKey)
           return false;

         if( !this->rsa->sign(message))
           return false;

         this->aes->modifyParam( aesKey );
         app = this->aes->encryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setSignature(app->getSignature(),app->getSignatureLen());
         message->setChosenColumn( app->getChosenColumn(), app->getChosenColumnLength());
         delete app;
         break;

         default:
           verbose<<"--> [CipherClient][fromSecureForm] Error, MessageType not supported:"<<message->getMessageType()<<'\n';     
     }
   return true;
  }

/*---------------fromSecureForm function*----------------------------------------------------- */
  bool CipherClient::fromSecureForm( Message* message , string username , SessionKey* aesKey )
  {
    if(!message)
    {
      verbose<<"-->[CipherClient][fromSecureForm] Error, null pointer message"<<'\n';
      return false;
    }

    Message* app;
    switch( message->getMessageType())
    {
      case CERTIFICATE:
        if(!rsa->extractServerKey(message->getServerCertificate(),message-> getServerCertificateLength()))
        {
          return false;
        }
        return rsa->clientVerifySignature( *message ,true);
       
       case LOGIN_OK:
         return rsa->clientVerifySignature( *message ,true);

       case ERROR:
         return rsa->clientVerifySignature( *message ,true);

       case LOGIN_FAIL:
         return rsa->clientVerifySignature( *message ,true); 
      
       case USER_LIST:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setUserList( app->getUserList(), app->getUserListLen() );
         delete app;
         break;  

       case RANK_LIST:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setRankList( app->getRankList(), app->getRankListLen() );
         delete app;
         break;

       case REJECT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         delete app;
         break;

       case ACCEPT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         delete app;
         break;

       case GAME_PARAM:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setNetInformations(app->getNetInformations(),app->getNetInformationsLength());
         delete app;
         if(!rsa->extractAdversaryKey(message->getNetInformations(),message->getNetInformationsLength()))
         {
           return false;
         } 
         break; 

       case MATCH:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         delete app;
         break;  

       case WITHDRAW_OK:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         delete app;
         break; 

       case ACK:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         delete app;
         break;  

       case MOVE:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setChosenColumn( app->getChosenColumn(), app->getChosenColumnLength());
         delete app;
         break;

       case CHAT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setMessage( app->getMessage(), app->getMessageLength());
         delete app;
         break;

       case DISCONNECT:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         delete app;
         break;   
/*
       case ERROR:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         delete app;
         break;
*/
       case GAME:
         if(!aesKey)
           return false;
         this->aes->modifyParam( aesKey );
         app = this->aes->decryptMessage(*message);
         if(app == nullptr)
         {
           return false;
         }
         message->setChosenColumn( app->getChosenColumn(), app->getChosenColumnLength());
         delete app;
         rsa->clientVerifySignature(*message,false); 
         break;
            
         default:
           vverbose<<"--> [CipherClient][fromSecureForm] Error, messageType not supported:"<<message->getMessageType()<<'\n';
         return false;    
    }
    return true;
  }

}

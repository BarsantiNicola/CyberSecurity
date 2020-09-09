#include"MainClient.h"
namespace client
{
  void MainClient::timerHandler(long secs)
  {
    while(true)
    {
      lck_time.lock();
      if(time!=0)
      {
        lck_time.unlock();
        sleep(SLEEP_TIME);
        lck_time.lock();
        --time;
        lck_time.unlock();
      }
      else
      {
        time_expired=true;
        lck_time.unlock();
      }
    }
   
  }
  bool MainClient::loginProtocol(Message message)//DA FINIRE
  {
    bool res;
    bool connection_res;
    bool socketIsClosed=false;
    if(message.getMessageType()==LOGIN_REQ)
    {
      res=connection_manager.sendMessage(message,connection_manager.getserverSocket(),&socketIsClosed,nullptr,0); 
      while(socketIsClosed)
      {
        connection_res=rescreateConnectionWithServerTCP(serverIP,serverPort);
        if(!connection_res)
          return false;
        res=connection_manager.sendMessage(message,connection_manager.getserverSocket(),&socketIsClosed,nullptr,0); 
      }
      return res;
    }
    if(message.getMessageType()==LOGIN_OK)
    {
      return true;
    }
    else
    {
      return false;
    }
       
  }


  Message* MainClient::createMessage(MessageType type, const char* param,unsigned char* g_param,int g_paramLen,SessionKey* aesKey,MessageGameType messageGameType)
  {
    NetMessage* partialKey;
    NetMessage* net;
    bool cipherRes=false;
    Message* message = new Message();
    switch(type)
    {
      case CERTIFICATE_REQ:
        message->setMessageType( CERTIFICATE_REQ );
        message->setNonce(0);
        break;
      case LOGIN_REQ:
        message->setMessageType( LOGIN_REQ );
        message->setNonce(this->nonce);
        message->setPort( this->myPort );
        message->setUsername(param );
        cipherRes=cipher_client->toSecureForm( Messamessage,aesKey );
        this->nonce++;
        break;
        
      case KEY_EXCHANGE:
        message->setMessageType( KEY_EXCHANGE );
        message->setNonce(this->nonce);
        partialKey = this->cipher_client->getPartialKey();
        message->set_DH_key( partialKey->getMessage(), partialKey->length() );
        cipherRes=this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case USER_LIST_REQ:
        message->setMessageType(USER_LIST_REQ);
        message->setNonce(this->nonce);
        cipherRes =this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case RANK_LIST_REQ:
        message->setMessageType( RANK_LIST_REQ );
        message->setNonce(this->nonce);
        cipherRes =this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case LOGOUT_REQ:
        message->setMessageType( LOGOUT_REQ );
        message->setNonce(this->nonce);
        message =this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case ACCEPT:
        message->setMessageType( ACCEPT );
        message->setNonce(this->nonce);
        message->setAdversary_1(param);
        message->setAdversary_2(this->username.c_str());
        message = this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case REJECT:
        message->setMessageType( REJECT );
        message->setNonce(this->nonce);
        message->setAdversary_1(param );
        message->setAdversary_2(this->username.c_str());
        cipherRes = this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case WITHDRAW_REQ:
        message->setMessageType( WITHDRAW_REQ );
        message->setNonce(this->nonce);
        message->setUsername(this->username);
        cipherRes = this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case MATCH:
        message->setMessageType( MATCH );
        message->setNonce(this->nonce);
        message->setUsername(string(param) );
        cipherRes = this->cipher_client->toSecureForm( message,aesKey );
       // net = Converter::encodeMessage(MATCH, *message );                //da vedere l'utilità in caso cancellare
       // message = this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case DISCONNECT:
        message->setMessageType( DISCONNECT );
        message->setNonce(this->nonce);
        message->setUsername(string(param) );
        cipherRes = this->cipher_client->toSecureForm( message,aesKey );
        //net = Converter::encodeMessage(MATCH, *message );               //da vedere l'utilità in caso cancellare
        //message = this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case ACK:
        message->setMessageType(ACK);
        switch(messageGameType)
        {
          case MOVE_TYPE:
            message->setCurrent_Token(this->currentToken);
            this->currentToken++;
            break;
          
          case CHAT_TYPE:
            message->setCurrent_Token(this->currTokenChat);
            this->currTokenChat++;
            break;

          case NO_GAME_TYPE_MESSAGE:
            return nullptr;

        }
        cipherRes = this->cipher_client->toSecureForm( message,aesKey );
        break;

      case CHAT:
        message->setMessageType(CHAT);     
        message->setCurrent_Token(this->currTokenChat);
        if( g_param==nullptr||aesKey==nullptr)
          return nullptr;
        message->setMessage( g_param,g_paramLen );
        cipherRes = this->cipher_client->toSecureForm( message,aesKey );
        this->currTokenChat++;
        break;

     case GAME:
        message->message->setMessageType(CHAT); 
        message->setCurrent_Token(this->currentToken);
        message->setMessage( g_param,g_paramLen );
        setChosenColumn( unsigned char* chosen_column, unsigned int len );
        cipherRes=cipher_client->toSecureForm( Messamessage,aesKey );
        break;

     case GAME:
        message->message->setMessageType(CHAT); 
        message->setCurrent_Token(this->currentToken);
        message->setMessage( g_param,g_paramLen );
        setChosenColumn( unsigned char* chosen_column, unsigned int len );
        cipherRes=cipher_client->toSecureForm( Messamessage,aesKey );
        break;
    }
    if(!cipherRes)
      return nullptr;
    return message;
  }
 
  unsigned char* MainClient::concTwoField(unsigned char* firstField,unsigned int firstFieldSize,unsigned char* secondField,unsigned int secondFieldSize,unsigned char separator,unsigned int numberSeparator)
  {
    unsigned char* app=new unsigned char*[firstFieldSize+secondFieldSize+numberSeparator];
    for(int i=0;i<firstFieldSize;++i)
    {
      app[i]=firstField[i];
    }
    for(int i=firstFieldSize;i<(firstFieldSize+numberSeparator);i++)
    {
      app[i]=separator;
    }
    for(int i=(firstFieldSize+numberSeparator);i<(firstFieldSize+numberSeparator+secondFieldSize);++i)
    {
      app[i]=secondField [i-(firstFieldSize+numberSeparator)];
    }
    return app;
  }
}

#include"Game.h"
#include<string>
#include<thread>
#include<termios.h>
#include<unistd.h>
#include"../cipher/CipherClient.h"
#include"../utility/Message.h"
#include"../utility/NetMessage.h"
#include"../utility/Converter.h"
//#include"ChallengeInformation.h"
#include"ChallengeRegister.h"
#include"TextualInterfaceManager.h"
#include"../utility/ConnectionManager.h"
#include<mutex>
#include<exception>
#include<vector>
#include<sstream>
#define SLEEP_TIME 1000
using namespace utility;
namespace client
{
  enum MessageGameType{
        NO_GAME_TYPE_MESSAGE,
        MOVE_TYPE,
        CHAT_TYPE
    };
  
  enum ClientPhase
  {
    MAIN_INTERFACE_PHASE,
    LOGIN_PHASE,
    LOGOUT_PHASE,
    REJECT_PHASE,
    ACCEPT_PHASE,
    USER_LIST_PHASE,
    RANK_LIST_PHASE,
    MATCH_PHASE,
    NO_PHASE

  };  

  class MainClient
  {
    private:
      long timer=15;
      bool time_expired=false;
      bool notConnected=true;
      bool startChallenge=false;
      bool implicitUserListReq=false;
      int nonce;
      bool logged=false;
      ClientPhase clientPhase= ClientPhase::NO_PHASE;
      int currentToken;//da inizializzare nel main
      int currTokenChat;//da inizializzare nel main
      const char* serverIP="127.0.0.1";
      int serverPort=12345;
      int myPort=1235;
      const char* myIP="127.0.0.1";
      bool sendImplicitUserListReq();
      string username = "";
      string adv_username_1 = "";
      string challenged_username = "";
      Game* game;
      cipher::SessionKey* aesKeyServer;
      cipher::SessionKey* aesKeyClient;
      ChallengeRegister* challenge_register=new ChallengeRegister();
      ConnectionManager* connection_manager;//da inizializzare nel main
      TextualInterfaceManager* textual_interface_manager;
      cipher::CipherClient* cipher_client;
      std::mutex mtx_time;
      std::unique_lock<std::mutex>* lck_time;//(mtx_time,std::defer_lock);//da inizializzare nel main
      bool loginProtocol(std::string username,bool *socketIsClosed);//ok
      //bool signUpProtocol(Message message);
      string printableString(unsigned char* toConvert,int len);//ok
      bool sendChallengeProtocol(const char* adversaryUsername);
      bool receiveChallengeProtocol(Message* message);
      bool sendAcceptProtocol();
      bool sendRejectProtocol(const char* usernameAdv);
      bool reciveRejectProtocol(Message* message);
      bool errorHandler(Message* message);//ok
      bool sendRankProtocol();//ok
      bool receiveRankProtocol(Message* message);//ok
      bool certificateProtocol();//ok
      bool keyExchangeReciveProtocol(Message* message,bool exchangeWithServer);//ok
      bool sendReqUserListProtocol();//ok
      bool receiveUserListProtocol(Message* message);//ok
      bool disconnectProtocol(Message message);
      bool sendLogoutProtocol();//ok
      bool receiveLogoutProtocol(Message* message);//ok
      bool gameProtocol(Message message);
      void timerHandler(long secs);
      bool comand(std::string comand_line);
      bool startConnectionServer(const char* myIP,int myPort);
      int countOccurences(string source,string searchFor);
      Message* createMessage(MessageType type, const char* param,unsigned char* g_param,int g_paramLen,cipher::SessionKey* aesKey,MessageGameType messageGameType);
      unsigned char* concTwoField(unsigned char* firstField,unsigned int firstFieldSize,unsigned char* secondField,unsigned int secondFieldSize,unsigned char separator,unsigned int numberSeparator);

      bool deconcatenateTwoField(unsigned char* originalField,unsigned int originalFieldSize,unsigned char* firsField,unsigned int* firstFieldSize,unsigned char* secondField,unsigned int* secondFieldSize,unsigned char separator,unsigned int numberSeparator);//ok

    public:
      MainClient(const char* ipAddr , int port ); 
      ~MainClient();
      void client();//ok
  };


}

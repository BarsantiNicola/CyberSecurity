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
#define SLEEP_TIME 1000
using namespace utility;
namespace client
{
  enum MessageGameType{
        NO_GAME_TYPE_MESSAGE,
        MOVE_TYPE,
        CHAT_TYPE
    };

  class MainClient
  {
    private:
      long timer=15;
      bool time_expired=false;
      int nonce;
      bool logged=false;
      int currentToken;//da inizializzare nel main
      int currTokenChat;//da inizializzare nel main
      const char* serverIP="127.0.0.1";
      int serverPort=1234;
      int myPort=1235;
      const char* myIP="127.0.0.1";
      string username = "";
      string adv_username_1 = "";
      //string adv_username_2 = "";
      Game* game;
      cipher::SessionKey* aesKeyServer;
      cipher::SessionKey* aesKeyClient;
      ChallengeRegister* challenge_register;
      ConnectionManager* connection_manager;//da inizializzare nel main
      TextualInterfaceManager* textual_interface_manager;
      cipher::CipherClient* cipher_client;
      std::mutex mtx_time;
      std::unique_lock<std::mutex>* lck_time;//(mtx_time,std::defer_lock);//da inizializzare nel main
      bool loginProtocol(Message message,bool* socketIsClosed);
      //bool signUpProtocol(Message message);
      bool challengeProtocol(Message message);
      bool acceptProtocol(Message message);
      bool rejectProtocol(Message message);
      bool rankProtocol(Message message);
      bool certificateProtocol();
      bool keyExchangeReciveProtocol(Message* message,bool exchangeWithServer);
      bool userListProtocol(Message message);
      bool disconnectProtocol(Message message);
      bool logoutProtocol(Message message);
      bool matchProtocol(Message message);
      void timerHandler(long secs);
      bool comand(std::string comand_line);
      bool startConnectionServer(const char* myIP,int myPort);
      Message* createMessage(MessageType type, const char* param,unsigned char* g_param,int g_paramLen,cipher::SessionKey* aesKey,MessageGameType messageGameType);
      unsigned char* concTwoField(unsigned char* firstField,unsigned int firstFieldSize,unsigned char* secondField,unsigned int secondFieldSize,unsigned char separator,unsigned int numberSeparator);

      bool deconcatenateTwoField(unsigned char* originalField,unsigned int originalFieldSize,unsigned char* firsField,unsigned int* firstFieldSize,unsigned char* secondField,unsigned int* secondFieldSize,unsigned char separator,unsigned int numberSeparator);

    public:
      MainClient(const char* ipAddr , int port ); 
      void client();
  };


}

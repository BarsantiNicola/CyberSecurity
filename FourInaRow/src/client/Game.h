#include<iostream>
#include<string>
#include<vector>
#include<stdexcept>
#include<thread>
#define NUMBER_ROW 6
#define NUMBER_COLUMN 7
using namespace std;
namespace client
{
  class Game
  {
    private:
      long timer
      int currentToken=0;
      int nextToken;
      string chat="";
      int gameBoard[NUMBER_ROW][NUMBER_COLLUMN];
      bool gameControl;
      int chatLen;
   public:
      Game(int chatLen,bool gameControl);
      bool makeMove(int column,bool* gameFinish,bool* iWon,bool* adversaryWon,bool* tie,bool myMove);//da fare
      bool gameBoardIsFull();
      void updateTimer();//da revisionare
      bool availableColumn(int column);
      bool myControl();
      vector<int> availableColumns();
      void addMessageToChat(string message);


   private:
      bool controlAlignment(int row,int column,bool myMove);
      bool gameFinish(int row,int column,bool* iWon,bool* adversaryWon,bool* tie,bool myMove);//da fare
      void changeControl();
  };

}

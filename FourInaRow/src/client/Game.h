#include<iostream>
#include<string>
#include<vector>
#include<stdexcept>
#define NUBER_ROW 6
#define NUMBER_COLUMN 7
using namespace std;
namespace client
{
  class Game
  {
    private:
      long timer
      int currentToken;
      int nextToken;
      string chat="";
      int gameBoard[NUMBER_ROW][NUMBER_COLLUMN];
      bool gameControl;
      int chatLen;
   public:
      Game(int chatLen,bool gameControl);
      bool makeMove(int column,bool mymove);
      bool gameBoardIsFull();
      bool updateTimer();//da revisionare
      bool availableColumn(int column);
      bool myControl();
      vector<int> availableColumns();
      void addMessageToChat(string message);
      bool gameFinish(bool* iWon,bool* adversaryWon,bool* tie);
   private:
      bool controlAlineation(int row,int column);
      void changeControl();












  };

}

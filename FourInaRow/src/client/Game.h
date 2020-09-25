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
  enum StatGame
  {
    MOVE_OK,
    BAD_MOVE,
    GAME_FINISH,
    OUT_OF_BOUND,
    BAD_TURN,
    NULL_POINTER
  };
  class Game
  {
    private:
      long timer;
      string chat="";
      int gameBoard[NUMBER_ROW][NUMBER_COLUMN];
      bool gameControl;
      int chatLen;
   public:
      Game(int chatLen,bool gameControl);
      StatGame makeMove(int column,bool* iWon,bool* adversaryWon,bool* tie,bool myMove);//da fare
      
      void updateTimer();//da revisionare
      bool availableColumn(int column);
      bool myControl();
      vector<int> availableColumns();
      void addMessageToChat(string message);
      string printGameBoard();
   private:
      bool controlAlignment(int row,int column,bool myMove);
      bool gameFinish(int row,int column,bool* iWon,bool* adversaryWon,bool* tie,bool myMove);
      bool gameBoardIsFull();
      void changeControl();
  };

}

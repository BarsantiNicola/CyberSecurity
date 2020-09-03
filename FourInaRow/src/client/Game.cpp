#include"Game.h"
namespace client
{
  Game::Game(int chatLen,bool gameControl)
  {
    this->gameControl=gameControl;
    this->chatLen=chatLen;
    for(int i=0;i<NUMBER_ROW;++i)
    {
      for(int j=0;j<NUMBER_COLUMN;++j)
      {
        gameBoard[i][j]=0;
      }
    }

  }


  bool Game::gameBoardIsFull()
  {
    
    for(int j=0;j<NUMBER_COLUMN;++j)
    {
      if(gameBoard[0][j]==0)
      {
        return false;
      }
    }
    return true;
  }


  bool Game::availableColumn(int column)
  {
    if(column>NUMBER_COLUMN||column<0)
    {
      return false;
    }
    if(gameBoard[0][column]==0)
    {
      return true;
    }
    else
    {
      return false;
    }
  }


  bool Game::myControl()
  {
    return gameControl;
  }


  void Game::changeControl()
  {
    gameControl=!gameControl;
  }


  void Game::addMessageToChat(string message)
  {
    chat+=message;
    message+="\n";
  }
}

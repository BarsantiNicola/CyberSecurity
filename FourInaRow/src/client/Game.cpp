#include"Game.h"
namespace client
{
  Game::Game(int chatLen,bool gameControl)
  {
    this->gameControl=gameControl;
    this->chatLen=chatLen;
    timer=15;
    for(int i=0;i<NUMBER_ROW;++i)
    {
      gameBoard[i]=new int[NUMBER_COLUMN];
    }
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
    if(column>=NUMBER_COLUMN||column<0)
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

  void updateTimer()
  {
    //da progettare
  }

  void Game::addMessageToChat(string message)
  {
    chat+=message;
    message+="\n";
  }


  bool Game::controlAlignment(int row,int column,bool myMove)
  {
    int numberToControl=0;
    int column_index;
    int row_index;
    if(row>=NUMBER_ROW||row<0||column>=NUMBER_COLUMN||column<0)
    {
      return false;
    }

    if(myMove==true)
      numberToControl=1;
    else
      numberToControl=2;

    int numberAligned=1;
    //ciclo for di controllo alineamento a destra
    for(int j=column+1;j<NUMBER_COLUMN;j++)
    {
      if(gameBoard[row][j]==numberToControl)
      {
        ++numberAligned;
        if(numberAligned==4)
          return true;
      }
      else
      {
        break;
      }
    }
    //ciclo controllo alineamento a sinistra
    for(int j=column-1;j>=0;--j)
    {
      if(gameBoard[row][j]==numberToControl)
      {
        ++numberAligned;
        if(numberAligned==4)
          return true;
      }
      else
      {
        break;
      }
    }
    numberAligned=1;
    //ciclo controllo alineamento in alto
    for(int i=row-1;i>=0;--i)
    {
      if(gameBoard[i][column]==numberToControl)
      {
         ++numberAligned;
         if(numberAligned==4)
           return true;
      }
      else
      {
        break;
      }
    }
    //ciclo controllo allineamento in basso
  
    for(int i=row+1;i<NUMBER_ROW;++i)
    {
      if(gameBoard[i][column]==numberToControl)
      {
         ++numberAligned;
         if(numberAligned==4)
           return true;
      }
      else
      {
        break;
      }
    }
    numberAligned=1;
    //controllo allineamento in basso a destra
    column_index=column+1;
    row_index=row+1;
    while(row_index < NUMBER_ROW && column_index < NUMBER_COLUMN)
    {
      if(gameBoard[row_index][column_index]==numberToControl)
      {
         ++numberAligned;
         if(numberAligned==4)
           return true;
      }
      else
      {
        break;
      }
      ++row_index;
      ++column_index;
    }
    //controllo allineamento in alto a sinistra
    column_index=column-1;
    row_index=row-1;
    while(row_index>=0 && column_index>=0)
    {
      if(gameBoard[row_index][column_index]==numberToControl)
      {
         ++numberAligned;
         if(numberAligned==4)
           return true;
      }
      else
      {
        break;
      }
      --row_index;
     --column_index;
    }
    //controllo allineamento in alto a destra
    column_index=column+1;
    row_index=row-1;
    numberAligned=1;
    while(row_index>=0 && column_index < NUMBER_COLUMN)
    {
      if(gameBoard[row_index][column_index]==numberToControl)
      {
         ++numberAligned;
         if(numberAligned==4)
           return true;
      }
      else
      {
        break;
      }
      --row_index;
      ++column_index;
    }

    //controllo allineamento in basso a sinistra
    row_index=row+1;
    column_index=column-1;
    while(row_index<NUMBER_ROW && column_index>=0)
    {
      if(gameBoard[row_index][column_index]==numberToControl)
      {
         ++numberAligned;
         if(numberAligned==4)
           return true;
      }
      else
      {
        break;
      }
      ++row_index;
      --column_index;

    }
    return false;
  }
  
  bool Game::gameFinish(int row,int column,bool* iWon,bool* adversaryWon,bool* tie,bool myMove)
  {
    /*if(iWon==nullptr||adversaryWon==nullptr||tie==nullptr)
     {
       verbose<<"--> [Game][GameFinish] error nullptr in the parameter!!"<<'\n';
       throw invalid_argument("recived nullptr argument");
     }*/
    *tie=false;
    *adversaryWon=false;
    *iWon=false; 
    if(gameBoardIsFull())
    {
      if(!controlAlignment(row,column,myMove))
      {
        *tie=true;
        return true;
      }
      else
      {
        if(myMove==true)
          *iWon=true;
        else
          *adversaryWon=true;
        return true;
      }
    }
    else
    {
      if(!controlAlignment(row,column,myMove))
      {
        return false;
      }
      else
      {
        if(myMove==true)
          *iWon=true;
        else
          *adversaryWon=true;
        return true;
      }
    }      
    
  }
/*
the function makeMove permit to add a token in the matrix if the column is available
return false in case of non autorizate move
*/
  StatGame Game::makeMove(int column,bool* iWon,bool* adversaryWon,bool* tie,bool myMove)
  {
    int row=0;
    if(iWon==nullptr||adversaryWon==nullptr||tie==nullptr)
     {
       return StatGame::NULL_POINTER;
     }
    if(myMove!=gameControl)
    {
      return StatGame::BAD_TURN;
    }
    if(column<0||column>=NUMBER_COLUMN||row<0||row>=NUMBER_ROW )
    {
      return StatGame::OUT_OF_BOUND;
    }
    if(availableColumn(column)==false)
    {
       return StatGame::BAD_MOVE;
    }
    for(int i=NUMBER_ROW-1;i>=0;--i)
    {
      if(gameBoard[i][NUMBER_COLUMN]==0)
      {
        if(myMove)
          gameBoard[i][NUMBER_COLUMN]=1;
        else
          gameBoard[i][NUMBER_COLUMN]=2;
        row=i;
        break;
      }
        
    }
    
    bool result=gameFinish(row,column,iWon,adversaryWon,tie,myMove);
    //changeControl and upload currrentToken
    changeControl();
    if(result)
      return StatGame::GAME_FINISH;
    else
      return StatGame::MOVE_OK;
    
  }
  string Game::getChat()
  {
    return chat;
  }
  vector<int> Game::availableColumns()
  {
    vector<int> columnsFree;
    for(int i=0;i<NUMBER_COLUMN;i++)
    {
      
      if(availableColumn(i))
      {
        columnsFree.push_back(i);
      }
    }
    return columnsFree;
  }

  string Game::printGameBoard()
  {
    string ret="";
    string app;
    for(int i=0;i<NUMBER_ROW;i++)
    {
      for(int j=0;j<NUMBER_COLUMN;++j)
      {
        switch(gameBoard[i][j])
        {
          case 0:
            app=" ";
            break;
      
         case 1:
           app="O";
           break;
 
        case 2:
          app="X";
          break;
        default:
          return "";
        }
        ret+=" " + app + " ";
        if(j!=(NUMBER_COLUMN-1))
          ret+="|";
      }
      ret+='\n';
    }
    return ret;
  }
  /*int (*Game::getGameBoard())[NUMBER_COLUMN]
  {
    return gameBoard;
  } */
  int ** Game::getGameBoard()
  {
    return (int**)gameBoard;//controllare sicurezza
  }
  Game::~Game()
  {
   
    for(int i=0;i<NUMBER_ROW;i++)
    {
      delete []gameBoard[i];
    }
    delete []gameBoard;
   
  }
}

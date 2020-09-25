
#include "MatchInformation.h"

namespace server{

    MatchInformation::MatchInformation( string challenger, string challenged ){

        this->challenger = challenger;
        this->challenged = challenged;
        this->status = OPENED;
        this->token = 0;
        this->control = false;

        if( NUMBER_ROW <= 0 || NUMBER_COLUMN <= 0 )
            this->nMoves = 0;
        else
            this->nMoves = NUMBER_ROW*NUMBER_COLUMN;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           GETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    string MatchInformation::getChallenger(){

        return this->challenger;

    }
    string MatchInformation::getChallenged(){

        return this->challenged;

    }

    MatchStatus MatchInformation::getStatus(){

        return this->status;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // sets the status of a match verifing that the correct logic is respected
    //   OPENED->ACCEPTED->READY->LOADED->STARTED   [CLOSED AVAILABLE ALWAYS]
    bool MatchInformation::setStatus( MatchStatus status ){

        if( status == ACCEPTED && this->status != OPENED ) return false;
        if( status == READY && this->status != ACCEPTED ) return false;
        if( status == STARTED && this->status != READY ) return false;

        this->status = status;
        return true;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                     PUBLIC FUNCTIONS                                      //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  used to register users moves during the challenge
    int MatchInformation::addChallengerMove( int chosen_col ){

        if( this->status != STARTED ) return -2;
        int row = -1;
        if( chosen_col <0 || chosen_col >= NUMBER_COLUMN)
            for( int a = NUMBER_ROW-1; a>0; a-- )
                if( !this->gameBoard[chosen_col][a] ){
                    row = a;
                    break;
                }
        if( row == -1 ){
            verbose<<"--> [MatchInformation][addChallengedMove] Error, column full"<<'\n';
            return -2;
        }
        this->gameBoard[chosen_col][row] = 2;
        return this->verifyGame( row, chosen_col,this->challenger );

    }

    //  used to register users moves during the challenge
    int MatchInformation::addChallengedMove( int chosen_col ){


        if( this->status != STARTED ) return -2;
        int row = -1;
        if( chosen_col <0 || chosen_col >= NUMBER_COLUMN)
        for( int a = NUMBER_ROW-1; a>0; a-- )
            if( !this->gameBoard[chosen_col][a] ){
                row = a;
                break;
            }
        if( row == -1 ){
            verbose<<"--> [MatchInformation][addChallengedMove] Error, column full"<<'\n';
            return -2;
        }
        this->gameBoard[chosen_col][row] = 2;
        return this->verifyGame( row, chosen_col,this->challenged );

    }

    //  the function calculates the result of the match to verify the winner
    int  MatchInformation::verifyMatch(){
        return 0;
    }

    //  the function controls if a user is present as a challenger or challenged
    bool MatchInformation::hasUser( string username ){

        return (this->challenger.compare(username) == 0) || (this->challenged.compare(username) == 0);
    }

    //  the function controls if a user is set as challenger
    bool MatchInformation::isChallenger( string username ){

        return this->challenger.compare(username) == 0;
    }

    int MatchInformation::getTotalMoves(){

        return this->nMoves;

    }
    bool MatchInformation::hasControl( string username ){

        return (!this->challenger.compare(username) && !control) || (!this->challenged.compare(username) && control);

    }

    int MatchInformation::verifyGame(int row, int column, string username) {

        if( !this->hasControl(username))
            return -2;

        int userTraduction = this->isChallenger(username)?1:2;

        int result = this->controlAlignment( row, column, userTraduction );
        if( result != -1 ) this->nMoves-= 1;
        this->control = !this->control;
        switch( result ){

            case -1:case 1:
                return result;
            case 0:
                if( !nMoves ) return 2;
                return result;

        }

        return -2;

    }

    int MatchInformation::controlAlignment( int row,int column,bool myMove){

        int numberToControl=0;
        int column_index;
        int row_index;
        if(row>=NUMBER_ROW||row<0||column>=NUMBER_COLUMN||column<0)
            return -1;

        if(myMove==true)
            numberToControl=1;
        else
            numberToControl=2;

        int numberAligned=1;
        //ciclo for di controllo alineamento a destra
        for(int j=column+1;j<NUMBER_COLUMN;j++)
            if(gameBoard[row][j]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }else
                break;

        //ciclo controllo alineamento a sinistra
        for(int j=column-1;j>=0;--j)
            if(gameBoard[row][j]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }else
                break;

        numberAligned=1;
        //ciclo controllo alineamento in alto
        for(int i=row-1;i>=0;--i)
            if(gameBoard[i][column]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }else
                break;


        //ciclo controllo allineamento in basso

        for(int i=row+1;i<NUMBER_ROW;++i)
            if(gameBoard[i][column]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }else
                break;

        numberAligned=1;
        //controllo allineamento in basso a destra
        column_index=column+1;
        row_index=row+1;
        while(row_index < NUMBER_ROW && column_index < NUMBER_COLUMN){
            if(gameBoard[row_index][column_index]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }else
                break;

            ++row_index;
            ++column_index;
        }
        //controllo allineamento in alto a sinistra
        column_index=column-1;
        row_index=row-1;
        while(row_index>=0 && column_index>=0){
            if(gameBoard[row_index][column_index]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }else
                break;

            --row_index;
            --column_index;
        }
        //controllo allineamento in alto a destra
        column_index=column+1;
        row_index=row-1;
        numberAligned=1;
        while(row_index>=0 && column_index < NUMBER_COLUMN){
            if(gameBoard[row_index][column_index]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }else
                break;

            --row_index;
            ++column_index;
        }

        //controllo allineamento in basso a sinistra
        row_index=row+1;
        column_index=column-1;
        while(row_index<NUMBER_ROW && column_index>=0){
            if(gameBoard[row_index][column_index]==numberToControl){
                ++numberAligned;
                if(numberAligned==4)
                    return 1;
            }
            else
                break;

            ++row_index;
            --column_index;
        }
        return 0;

    }

    bool MatchInformation::verifyToken( int token ){

        if( this->token == 0 || this->token == token-1 ){
            this->token = token;
            return true;
        }

        return false;
    }
}
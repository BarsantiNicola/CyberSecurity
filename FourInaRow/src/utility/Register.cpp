#include"Register.h"
#include<limits.h>


namespace utility
{ 
   template<typename T>
   Register<T>::Register(){
  /* dataList=vector<T>();
   vector<T>().swap(dataList);*/
   vverbose<<"-->[Register][Costructor] Object created"<<'\n';
   //cout<<"vector size: "<<dataList.size()<<endl;
  }

/*
--------------------function getData(unsigned pos)-------------------------------------
this function return a data in a position pos if the pos is invalid return NULL


*/
  template<typename T>

  T* Register<T>::getDatafromIndex(unsigned int pos)
  {
    if(pos>= dataList.size()||pos<0||pos>SIZE_MAX/sizeof(int))
    {
      verbose<<"-->[Register][getData] Position: "<<(int)pos <<" not valid"<<'\n';
      
      return NULL;
    }
    else
       vverbose<<"-->[Register][getData] The data was returned succesfully at the position: "<<(int)pos<<'\n';
      try
      {
        return &dataList.at(pos);
       }
      
      catch(const out_of_range& e)
      {
        verbose<<"-->[Register][getData] error to access on data"<<'\n';
        return NULL;
      }

  }
 template<typename T>
  T* Register<T>::getData(T data)
  {
    try
    {
      for(int i=0;i<dataList.size();i++)
      {
        if(dataList.at(i)==data)
        {
           vverbose<<"-->[Register][getData] the data was returned successfully"<<'\n';
           
           return &dataList.at(i);
        }
      }
    verbose<<"-->[Register][getData] data not found"<<'\n';
    return NULL;
    }
    catch(const out_of_range& e)
    {
      verbose<<"-->[Register][getData] error to access on data"<<'\n';
      return NULL;
     }
  }
/* 
-----------------------------function removeData(T data)---------------------------
remove a data from the dataList vector and in case of success return true otherwise the fuctuion return false value
*/
  template<typename T>
  bool Register<T>::removeData(T data)
  {
    try
    {
      for(int i=0;i<dataList.size();i++)
      {
        if(dataList.at(i)==data)
        {
           vverbose<<"-->[Register][removeData] the data was removed successfully"<<'\n';
           dataList.erase(dataList.begin()+(i));
           return true;
        }
      }
    verbose<<"-->[Register][removeData] data not found"<<'\n';
    return false;
    }
    catch(const out_of_range& e)
    {
      verbose<<"-->[Register][removeData] error to access on data"<<'\n';
      return false;
     }
  }


/*---------------------------------------Function addData(T data)---------------------------
This function return true if the data was added succesfully, false in the unsuccesfully case
*/
  template<typename T>
  bool Register<T>::addData(T data)
  {
    //cout<<"Previos vector size: "<<dataList.size()<<endl;
    try
    {
      dataList.emplace_back(data);
    }
    catch(const bad_alloc& e)
    {
      verbose<<"-->[Register][addData] Error bad allocation"<<'\n';
      return false;
    }
    vverbose<<"-->[Register][addData] the data was added successfully"<<'\n';
    //cout<<(int)dataList.size()<<endl;
    return true;
  }
/*
--------------------------------Function ~Register()---------------------------------------
*/
  template<typename T>
  Register<T>::~Register()
  {
    vector<T>().swap(dataList);
  }
  template class Register<int>; 

}

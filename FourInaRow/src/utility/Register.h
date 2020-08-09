#include<stdexcept>
#include<vector>
using namespace std;
namespace utility{

 template<typename T>
 class Register{
  protected:
   vector<T> dataList;
  public:
   Register();
   bool removeData(T);
   ~Register();
  protected:
   bool addData(T);
   T getData(int);
 };
}


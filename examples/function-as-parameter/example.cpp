// C++ program to pass function as a
// pointer to any function
  
#include <iostream>
using namespace std;
  
// Function that add two numbers
int add(int x, int y)
{
    return x + y;
}
  
// Function that multiplies two
// numbers
int multiply(int x, int y)
{
    return x * y;
}
  
// Function that takes a pointer
// to a function
int invoke(int x, int y,
           int (*func)(int, int))
{
    return func(x, y);
}
  
// Driver Code
int main()
{
    // Pass pointers to add & multiply
    // function as required
    cout << "Addition of 20 and 10 is ";
    cout << invoke(20, 10, &add)
         << '\n';
  
    cout << "Multiplication of 20"
         << " and 10 is ";
    cout << invoke(20, 10, &multiply)
         << '\n';
  
    return 0;
}

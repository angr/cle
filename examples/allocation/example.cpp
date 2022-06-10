// Functions to test register allocation
#include <complex.h>

#include <iostream>

// Integral Types
extern "C" void test_bool(bool x) {}
extern "C" void test_ptr_bool(bool* x) {}
extern "C" void test_ptr_ptr_bool(bool** x) {}
extern "C" void test_char(char x) {}
extern "C" void test_ptr_char(char* x) {}
extern "C" void test_ptr_ptr_char(char** x) {}
extern "C" void test_short(short x) {}
extern "C" void test_ptr_short(short* x) {}
extern "C" void test_ptr_ptr_short(short** x) {}
extern "C" void test_int(int x) {}
extern "C" void test_ptr_int(int* x) {}
extern "C" void test_ptr_ptr_int(int** x) {}
extern "C" void test_long(long x) {}
extern "C" void test_ptr_long(long* x) {}
extern "C" void test_ptr_ptr_long(long** x) {}
extern "C" void test_long_long(long long x) {}
extern "C" void test_ptr_long_long(long long* x) {}
extern "C" void test_ptr_ptr_long_long(long long** x) {}

// Signed Integral Types
extern "C" void test_signed(signed x) {}
extern "C" void test_ptr_signed(signed* x) {}
extern "C" void test_ptr_ptr_signed(signed** x) {}
extern "C" void test_signed_char(signed char x) {}
extern "C" void test_ptr_signed_char(signed char* x) {}
extern "C" void test_ptr_ptr_signed_char(signed char** x) {}
extern "C" void test_signed_short(signed short x) {}
extern "C" void test_ptr_signed_short(signed short* x) {}
extern "C" void test_ptr_ptr_signed_short(signed short** x) {}
extern "C" void test_signed_int(signed int x) {}
extern "C" void test_ptr_signed_int(signed int* x) {}
extern "C" void test_ptr_ptr_signed_int(signed int** x) {}
extern "C" void test_signed_long(signed long x) {}
extern "C" void test_ptr_signed_long(signed long* x) {}
extern "C" void test_ptr_ptr_signed_long(signed long** x) {}
extern "C" void test_signed_long_long(signed long long x) {}
extern "C" void test_ptr_signed_long_long(signed long long* x) {}
extern "C" void test_ptr_ptr_signed_long_long(signed long long** x) {}

// Unsigned Integral Types
extern "C" void test_unsigned(unsigned x) {}
extern "C" void test_ptr_unsigned(unsigned* x) {}
extern "C" void test_ptr_ptr_unsigned(unsigned** x) {}
extern "C" void test_unsigned_char(unsigned char x) {}
extern "C" void test_ptr_unsigned_char(unsigned char* x) {}
extern "C" void test_ptr_ptr_unsigned_char(unsigned char** x) {}
extern "C" void test_unsigned_short(unsigned short x) {}
extern "C" void test_ptr_unsigned_short(unsigned short* x) {}
extern "C" void test_ptr_ptr_unsigned_short(unsigned short** x) {}
extern "C" void test_unsigned_int(unsigned int x) {}
extern "C" void test_ptr_unsigned_int(unsigned int* x) {}
extern "C" void test_ptr_ptr_unsigned_int(unsigned int** x) {}
extern "C" void test_unsigned_long(unsigned long x) {}
extern "C" void test_ptr_unsigned_long(unsigned long* x) {}
extern "C" void test_ptr_ptr_unsigned_long(unsigned long** x) {}
extern "C" void test_unsigned_long_long(unsigned long long x) {}
extern "C" void test_ptr_unsigned_long_long(unsigned long long* x) {}
extern "C" void test_ptr_ptr_unsigned_long_long(unsigned long long** x) {}

// Floating Point Types
extern "C" void test_float(float x) {}
extern "C" void test_ptr_float(float* x) {}
extern "C" void test_ptr_ptr_float(float** x) {}
extern "C" void test_double(double x) {}
extern "C" void test_ptr_double(double* x) {}
extern "C" void test_ptr_ptr_double(double** x) {}
extern "C" void test_long_double(long double x) {}
extern "C" void test_ptr_long_double(long double* x) {}
extern "C" void test_ptr_ptr_long_double(long double** x) {}
extern "C" void test_float__Complex(float _Complex x) {}
extern "C" void test_ptr_float__Complex(float _Complex* x) {}
extern "C" void test_ptr_ptr_float__Complex(float _Complex** x) {}
extern "C" void test_double__Complex(double _Complex x) {}
extern "C" void test_ptr_double__Complex(double _Complex* x) {}
extern "C" void test_ptr_ptr_double__Complex(double _Complex** x) {}
extern "C" void test_long_double__Complex(long double _Complex x) {}
extern "C" void test_ptr_long_double__Complex(long double _Complex* x) {}
extern "C" void test_ptr_ptr_long_double__Complex(long double _Complex** x) {}

// UTF Types
extern "C" void test_wchar_t(wchar_t x) {}
extern "C" void test_ptr_wchar_t(wchar_t* x) {}
extern "C" void test_ptr_ptr_wchar_t(wchar_t** x) {}
extern "C" void test_char16_t(char16_t x) {}
extern "C" void test_ptr_char16_t(char16_t* x) {}
extern "C" void test_ptr_ptr_char16_t(char16_t** x) {}
extern "C" void test_char32_t(char32_t x) {}
extern "C" void test_ptr_char32_t(char32_t* x) {}
extern "C" void test_ptr_ptr_char32_t(char32_t** x) {}

// Size Types
extern "C" void test_size_t(size_t x) {}
extern "C" void test_ptr_size_t(size_t* x) {}
extern "C" void test_ptr_ptr_size_t(size_t** x) {}
extern "C" void test_intmax_t(intmax_t x) {}
extern "C" void test_ptr_intmax_t(intmax_t* x) {}
extern "C" void test_ptr_ptr_intmax_t(intmax_t** x) {}
extern "C" void test_uintmax_t(uintmax_t x) {}
extern "C" void test_ptr_uintmax_t(uintmax_t* x) {}
extern "C" void test_ptr_ptr_uintmax_t(uintmax_t** x) {}
extern "C" void test_intptr_t(intptr_t x) {}
extern "C" void test_ptr_intptr_t(intptr_t* x) {}
extern "C" void test_ptr_ptr_intptr_t(intptr_t** x) {}
extern "C" void test_uintptr_t(uintptr_t x) {}
extern "C" void test_ptr_uintptr_t(uintptr_t* x) {}
extern "C" void test_ptr_ptr_uintptr_t(uintptr_t** x) {}

// Fixed-width Integral Types
extern "C" void test_int8_t(int8_t x) {}
extern "C" void test_ptr_int8_t(int8_t* x) {}
extern "C" void test_ptr_ptr_int8_t(int8_t** x) {}
extern "C" void test_int16_t(int16_t x) {}
extern "C" void test_ptr_int16_t(int16_t* x) {}
extern "C" void test_ptr_ptr_int16_t(int16_t** x) {}
extern "C" void test_int32_t(int32_t x) {}
extern "C" void test_ptr_int32_t(int32_t* x) {}
extern "C" void test_ptr_ptr_int32_t(int32_t** x) {}
extern "C" void test_int64_t(int64_t x) {}
extern "C" void test_ptr_int64_t(int64_t* x) {}
extern "C" void test_ptr_ptr_int64_t(int64_t** x) {}
extern "C" void test_int_fast8_t(int_fast8_t x) {}
extern "C" void test_ptr_int_fast8_t(int_fast8_t* x) {}
extern "C" void test_ptr_ptr_int_fast8_t(int_fast8_t** x) {}
extern "C" void test_int_fast16_t(int_fast16_t x) {}
extern "C" void test_ptr_int_fast16_t(int_fast16_t* x) {}
extern "C" void test_ptr_ptr_int_fast16_t(int_fast16_t** x) {}
extern "C" void test_int_fast32_t(int_fast32_t x) {}
extern "C" void test_ptr_int_fast32_t(int_fast32_t* x) {}
extern "C" void test_ptr_ptr_int_fast32_t(int_fast32_t** x) {}
extern "C" void test_int_fast64_t(int_fast64_t x) {}
extern "C" void test_ptr_int_fast64_t(int_fast64_t* x) {}
extern "C" void test_ptr_ptr_int_fast64_t(int_fast64_t** x) {}
extern "C" void test_int_least8_t(int_least8_t x) {}
extern "C" void test_ptr_int_least8_t(int_least8_t* x) {}
extern "C" void test_ptr_ptr_int_least8_t(int_least8_t** x) {}
extern "C" void test_int_least16_t(int_least16_t x) {}
extern "C" void test_ptr_int_least16_t(int_least16_t* x) {}
extern "C" void test_ptr_ptr_int_least16_t(int_least16_t** x) {}
extern "C" void test_int_least32_t(int_least32_t x) {}
extern "C" void test_ptr_int_least32_t(int_least32_t* x) {}
extern "C" void test_ptr_ptr_int_least32_t(int_least32_t** x) {}
extern "C" void test_int_least64_t(int_least64_t x) {}
extern "C" void test_ptr_int_least64_t(int_least64_t* x) {}
extern "C" void test_ptr_ptr_int_least64_t(int_least64_t** x) {}

// Unsigned Fixed-width Integral Types
extern "C" void test_uint8_t(uint8_t x) {}
extern "C" void test_ptr_uint8_t(uint8_t* x) {}
extern "C" void test_ptr_ptr_uint8_t(uint8_t** x) {}
extern "C" void test_uint16_t(uint16_t x) {}
extern "C" void test_ptr_uint16_t(uint16_t* x) {}
extern "C" void test_ptr_ptr_uint16_t(uint16_t** x) {}
extern "C" void test_uint32_t(uint32_t x) {}
extern "C" void test_ptr_uint32_t(uint32_t* x) {}
extern "C" void test_ptr_ptr_uint32_t(uint32_t** x) {}
extern "C" void test_uint64_t(uint64_t x) {}
extern "C" void test_ptr_uint64_t(uint64_t* x) {}
extern "C" void test_ptr_ptr_uint64_t(uint64_t** x) {}
extern "C" void test_uint_fast8_t(uint_fast8_t x) {}
extern "C" void test_ptr_uint_fast8_t(uint_fast8_t* x) {}
extern "C" void test_ptr_ptr_uint_fast8_t(uint_fast8_t** x) {}
extern "C" void test_uint_fast16_t(uint_fast16_t x) {}
extern "C" void test_ptr_uint_fast16_t(uint_fast16_t* x) {}
extern "C" void test_ptr_ptr_uint_fast16_t(uint_fast16_t** x) {}
extern "C" void test_uint_fast32_t(uint_fast32_t x) {}
extern "C" void test_ptr_uint_fast32_t(uint_fast32_t* x) {}
extern "C" void test_ptr_ptr_uint_fast32_t(uint_fast32_t** x) {}
extern "C" void test_uint_fast64_t(uint_fast64_t x) {}
extern "C" void test_ptr_uint_fast64_t(uint_fast64_t* x) {}
extern "C" void test_ptr_ptr_uint_fast64_t(uint_fast64_t** x) {}
extern "C" void test_uint_least8_t(uint_least8_t x) {}
extern "C" void test_ptr_uint_least8_t(uint_least8_t* x) {}
extern "C" void test_ptr_ptr_uint_least8_t(uint_least8_t** x) {}
extern "C" void test_uint_least16_t(uint_least16_t x) {}
extern "C" void test_ptr_uint_least16_t(uint_least16_t* x) {}
extern "C" void test_ptr_ptr_uint_least16_t(uint_least16_t** x) {}
extern "C" void test_uint_least32_t(uint_least32_t x) {}
extern "C" void test_ptr_uint_least32_t(uint_least32_t* x) {}
extern "C" void test_ptr_ptr_uint_least32_t(uint_least32_t** x) {}
extern "C" void test_uint_least64_t(uint_least64_t x) {}
extern "C" void test_ptr_uint_least64_t(uint_least64_t* x) {}
extern "C" void test_ptr_ptr_uint_least64_t(uint_least64_t** x) {}

// Register Allocation - Null Type
extern "C" void test_void() {}

int main() {
  return 0;
}

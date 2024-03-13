__int64 __fastcall CanYouCatchMe[abi:cxx11](__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 v4; // rdx
  char v6[48]; // [rsp+20h] [rbp-20h] BYREF
  int v8; // [rsp+68h] [rbp+28h]

  v8 = a3;
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(a1, a2, a3, a4);
  if ( v8 > 15 )
  {
    CanYouCatchMe[abi:cxx11](a1, a2, (v8 >> 4), v6);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(a1, a2, v6, a4);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(a1, a2, v4, v6);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(
      a1,
      a2,
      a0123456789abcd[v8 % 16],
      a4);
  }
  else
  {
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(
      a1,
      a2,
      a0123456789abcd[v8],
      a4);
  }
  return a4;
}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  int v4; // er9
  __int64 v5; // rdx
  __int64 v6; // rdx
  __int64 v7; // rdx
  __int64 v8; // rdx
  __int64 v9; // rdx
  char v10; // bl
  __int64 v11; // rdx
  __int64 v12; // rax
  char v13; // bl
  __int64 v14; // rdx
  unsigned __int64 v15; // rbx
  unsigned __int64 v16; // rbx
  char *v17; // rax
  __int64 v18; // rdx
  bool v19; // bl
  __int64 v20; // rdx
  char *v21; // rax
  __int64 v22; // rdx
  char *v23; // rax
  __int64 v24; // rdx
  unsigned __int64 v25; // rbx
  __int64 v26; // rdx
  int v27; // er8
  int v28; // er9
  bool v29; // bl
  __int64 v30; // rdx
  __int64 v31; // rdx
  __int64 v32; // rdx
  char v34[32]; // [rsp+20h] [rbp-60h] BYREF
  char v35[32]; // [rsp+40h] [rbp-40h] BYREF
  char v36[47]; // [rsp+60h] [rbp-20h] BYREF
  char v37; // [rsp+8Fh] [rbp+Fh] BYREF
  char v38[32]; // [rsp+90h] [rbp+10h] BYREF
  char v39[32]; // [rsp+B0h] [rbp+30h] BYREF
  char v40[32]; // [rsp+D0h] [rbp+50h] BYREF
  char v41[36]; // [rsp+F0h] [rbp+70h] BYREF
  int k; // [rsp+114h] [rbp+94h]
  int j; // [rsp+118h] [rbp+98h]
  int i; // [rsp+11Ch] [rbp+9Ch]

  _main(argc, argv, envp);
  std::allocator<char>::allocator(argc, argv, v3, &v37);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string<std::allocator<char>>(
    argc,
    argv,
    "BKSEC{Welcome_to_reverse!!!}",
    v36,
    &v37,
    v4);
  std::allocator<char>::~allocator(argc, argv, v5, &v37);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(argc, argv, v6, v35);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(argc, argv, v7, v34);
  std::operator<<<std::char_traits<char>>(argc, argv, "Enter password: ", refptr__ZSt4cout);
  std::operator>><char>(argc, argv, v34, refptr__ZSt3cin);
  if ( std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(argc, argv, v8, v34) == 28 )
  {
    for ( i = 0; ; ++i )
    {
      v16 = i;
      if ( v16 >= std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(
                    argc,
                    argv,
                    v9,
                    v34) )
        break;
      for ( j = 0; ; ++j )
      {
        v15 = j;
        if ( v15 >= std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(
                      argc,
                      argv,
                      v14,
                      v36) )
          break;
        v10 = *std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                 argc,
                 argv,
                 i,
                 v34);
        v12 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(argc, argv, v11, v34);
        v13 = *std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                 argc,
                 argv,
                 v12 - j - 1,
                 v36) ^ v10;
        *std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](argc, argv, i, v34) = v13;
      }
    }
    for ( k = 0; ; ++k )
    {
      v25 = k;
      if ( v25 >= std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(
                    argc,
                    argv,
                    v14,
                    v34) )
        break;
      v17 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](argc, argv, k, v34);
      CanYouCatchMe[abi:cxx11](*&argc, argv, *v17, v38);
      v19 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(argc, argv, v18, v38) == 1;
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(argc, argv, v20, v38);
      if ( v19 )
      {
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(argc, argv, "0", v35);
        v21 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                argc,
                argv,
                k,
                v34);
        CanYouCatchMe[abi:cxx11](*&argc, argv, *v21, v39);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(argc, argv, v39, v35);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(
          argc,
          argv,
          v22,
          v39);
      }
      else
      {
        v23 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                argc,
                argv,
                k,
                v34);
        CanYouCatchMe[abi:cxx11](*&argc, argv, *v23, v40);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(argc, argv, v40, v35);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(
          argc,
          argv,
          v24,
          v40);
      }
    }
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(argc, argv, v35, v41);
    v29 = CheckKey(argc, argv, v26, v41, v27, v28);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(argc, argv, v30, v41);
    if ( v29 )
      std::operator<<<std::char_traits<char>>(argc, argv, "You are handsome", refptr__ZSt4cout);
    else
      std::operator<<<std::char_traits<char>>(argc, argv, "Try again to be handsome", refptr__ZSt4cout);
  }
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(argc, argv, v9, v34);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(argc, argv, v31, v35);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(argc, argv, v32, v36);
  return 0;
}
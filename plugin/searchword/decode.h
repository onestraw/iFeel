#include <iostream>
#include <string>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef WIN32
	#include <windows.h>
	#pragma warning(disable:4996)
#elif linux
	#include<wchar.h>
//	#define WCHAR wchar_t
	typedef unsigned short WCHAR;
	typedef unsigned char BYTE;
#endif
using namespace std;

/**
注：只能处理的搜索网页的url编码是utf-8或gb2312编码方式。
*/

/**
2部分；一个URL编码和解码的C++类。用于将提取的utf-8转换成GB2312类型。
学习连接：http://www.cnblogs.com/xiaoka/articles/2585189.html
*/
class strCoding
{
public:
	strCoding(void);
	~strCoding(void);

	void UTF_8ToGB2312(string &pOut, char *pText, int pLen);//utf_8转为gb2312
	void GB2312ToUTF_8(string& pOut, char *pText, int pLen); //gb2312 转utf_8
	string UrlGB2312(char * str);                           //urlgb2312编码
	string UrlUTF8(char * str);                             //urlutf8 编码
	string UrlUTF8Decode(string str);                  //urlutf8解码
	string UrlGB2312Decode(string str);                //urlgb2312解码

private:
	void Gb2312ToUnicode(WCHAR* pOut, char *gbBuffer);
	void UTF_8ToUnicode(WCHAR* pOut, char *pText);
	void UnicodeToUTF_8(char* pOut, WCHAR* pText);
	void UnicodeToGB2312(char* pOut, WCHAR uData);
	char CharToInt(char ch);
	char StrToBin(char *str);

};

void getInfo(string s, string &web, string &content);

int selftest();

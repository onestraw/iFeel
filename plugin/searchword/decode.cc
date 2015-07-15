#include "decode.h"
/**
1部分，数据和预处理。
写好webType ，webContentType， webDecodeType和webNum的值。
并执行前调用init()

webType中是搜索网站区别其它搜索网站的关键字
webContentType是对应搜索网站中搜索关键字的标志入口
webDecodeType是对应搜索网站url编码方式，0为utf-8，1为gb2312。
*/
const int webNum = 10;
string webType[] = {
	"google", "baidu", "bing", "wikipedia",
	"yahoo", "soso", "youdao", "www.so.com",
	"sogou", "sina"
};
string webContentTag[] = {
	"q", "wd", "q", "search",
	"p", "w", "q", "q",
	"query", "q"

};
int webDecodeType[] = {
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 1
};
map<string, int>webMap;
///使用前先调用init();
void init()
{
	webMap.clear();
	for (int i = 0; i < webNum; i++)
	{
		webMap[webType[i]] = i;
	}
}


strCoding::strCoding(void)
{
}

strCoding::~strCoding(void)
{
}
void strCoding::Gb2312ToUnicode(WCHAR* pOut, char *gbBuffer)
{
#ifdef WIN32
	::MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, gbBuffer, 2, pOut, 1);
#elif linux
	mbstowcs((wchar_t*)pOut, gbBuffer, 2);
#endif
	return;
}
void strCoding::UTF_8ToUnicode(WCHAR* pOut, char *pText)
{
	char* uchar = (char *)pOut;

	uchar[1] = ((pText[0] & 0x0F) << 4) + ((pText[1] >> 2) & 0x0F);
	uchar[0] = ((pText[1] & 0x03) << 6) + (pText[2] & 0x3F);

	return;
}

void strCoding::UnicodeToUTF_8(char* pOut, WCHAR* pText)
{
	// 注意 WCHAR高低字的顺序,低字节在前，高字节在后
	char* pchar = (char *)pText;

	pOut[0] = (0xE0 | ((pchar[1] & 0xF0) >> 4));
	pOut[1] = (0x80 | ((pchar[1] & 0x0F) << 2)) + ((pchar[0] & 0xC0) >> 6);
	pOut[2] = (0x80 | (pchar[0] & 0x3F));

	return;
}
void strCoding::UnicodeToGB2312(char* pOut, WCHAR uData)
{
#ifdef WIN32
	WideCharToMultiByte(CP_ACP, NULL, &uData, 1, pOut, sizeof(WCHAR), NULL, NULL);
#elif linux
	wcstombs(pOut, (const wchar_t*)uData, 2);
#endif
	return;
}

//做为解Url使用
char strCoding::CharToInt(char ch){
	if (ch >= '0' && ch <= '9')return (char)(ch - '0');
	if (ch >= 'a' && ch <= 'f')return (char)(ch - 'a' + 10);
	if (ch >= 'A' && ch <= 'F')return (char)(ch - 'A' + 10);
	return -1;
}
char strCoding::StrToBin(char *str){
	char tempWord[2];
	char chn;

	tempWord[0] = CharToInt(str[0]);                         //make the B to 11 -- 00001011
	tempWord[1] = CharToInt(str[1]);                         //make the 0 to 0 -- 00000000

	chn = (tempWord[0] << 4) | tempWord[1];                //to change the BO to 10110000

	return chn;
}


//UTF_8 转gb2312
void strCoding::UTF_8ToGB2312(string &pOut, char *pText, int pLen)
{
	char buf[4];
	char* rst = new char[pLen + (pLen >> 2) + 2];
	memset(buf, 0, 4);
	memset(rst, 0, pLen + (pLen >> 2) + 2);

	int i = 0;
	int j = 0;

	while (i < pLen)
	{
		if (*(pText + i) >= 0)
		{

			rst[j++] = pText[i++];
		}
		else
		{
			WCHAR Wtemp;


			UTF_8ToUnicode(&Wtemp, pText + i);

			UnicodeToGB2312(buf, Wtemp);

			unsigned short int tmp = 0;
			tmp = rst[j] = buf[0];
			tmp = rst[j + 1] = buf[1];
			tmp = rst[j + 2] = buf[2];

			//newBuf[j] = Ctemp[0];
			//newBuf[j + 1] = Ctemp[1];

			i += 3;
			j += 2;
		}

	}
	rst[j] = '\0';
	pOut = rst;
	delete[]rst;
}

//GB2312 转为 UTF-8
void strCoding::GB2312ToUTF_8(string& pOut, char *pText, int pLen)
{
	char buf[4];
	memset(buf, 0, 4);

	pOut.clear();

	int i = 0;
	while (i < pLen)
	{
		//如果是英文直接复制就可以
		if (pText[i] >= 0)
		{
			char asciistr[2] = { 0 };
			asciistr[0] = (pText[i++]);
			pOut.append(asciistr);
		}
		else
		{
			WCHAR pbuffer;
			Gb2312ToUnicode(&pbuffer, pText + i);

			UnicodeToUTF_8(buf, &pbuffer);

			pOut.append(buf);

			i += 2;
		}
	}

	return;
}
//把str编码为网页中的 GB2312 url encode ,英文不变，汉字双字节 如%3D%AE%88
string strCoding::UrlGB2312(char * str)
{
	string dd;
	size_t len = strlen(str);
	for (size_t i = 0; i<len; i++)
	{
		if (isalnum((BYTE)str[i]))
		{
			char tempbuff[2];
			sprintf(tempbuff, "%c", str[i]);
			dd.append(tempbuff);
		}
		else if (isspace((BYTE)str[i]))
		{
			dd.append("+");
		}
		else
		{
			char tempbuff[4];
			sprintf(tempbuff, "%%%X%X", ((BYTE*)str)[i] >> 4, ((BYTE*)str)[i] % 16);
			dd.append(tempbuff);
		}

	}
	return dd;
}

//把str编码为网页中的 UTF-8 url encode ,英文不变，汉字三字节 如%3D%AE%88

string strCoding::UrlUTF8(char * str)
{
	string tt;
	string dd;
	GB2312ToUTF_8(tt, str, (int)strlen(str));

	size_t len = tt.length();
	for (size_t i = 0; i<len; i++)
	{
		if (isalnum((BYTE)tt.at(i)))
		{
			char tempbuff[2] = { 0 };
			sprintf(tempbuff, "%c", (BYTE)tt.at(i));
			dd.append(tempbuff);
		}
		else if (isspace((BYTE)tt.at(i)))
		{
			dd.append("+");
		}
		else
		{
			char tempbuff[4];
			sprintf(tempbuff, "%%%X%X", ((BYTE)tt.at(i)) >> 4, ((BYTE)tt.at(i)) % 16);
			dd.append(tempbuff);
		}

	}
	return dd;
}
//把url GB2312解码
string strCoding::UrlGB2312Decode(string str)
{
	string output = "";
	char tmp[2];
	int i = 0, idx = 0, ndx, len = str.length();

	while (i<len){
		if (str[i] == '%'){
			tmp[0] = str[i + 1];
			tmp[1] = str[i + 2];
			output += StrToBin(tmp);
			i = i + 3;
		}
		else if (str[i] == '+'){
			output += ' ';
			i++;
		}
		else{
			output += str[i];
			i++;
		}
	}

	return output;
}
//把url utf8解码
string strCoding::UrlUTF8Decode(string str)
{
	string output = "";

	string temp = UrlGB2312Decode(str);//

	UTF_8ToGB2312(output, (char *)temp.data(), strlen(temp.data()));

	return output;

}

/**
3部分；提取搜索网站放到web中，提取内容的utf-8字符串放到content中, 匹配web的id 放到 type。
本部分，只支持处理baidu，goole，2中类型。其它类型，需要稍加修改。
*/

void getWebAndContext(string s, string &web, string &content, int &type)
{
	web = content = ""; type = -1;///
	string tmp;
	int len = s.size();
	int state = 0;

	for (int i = 0; i < len;)
	{
		if (s[i] == '/' && i + 1 < len && s[i + 1] == '/')///提取'//'到第一个'/'之间的字符串，存放到web。
		{
			i += 2;
			while (i < len && s[i] != '/')
			{
				web += s[i];
				i++;
			}
			for (int j = 0; j < webNum; j++)
			{
				if (web.find(webType[j]) != string::npos)
				{
					type = j; break;
				}
			}
			i++;
		}
		else if (s[i] == '?' || s[i] == '&')
		{
			i++;
			tmp = "";
			while (i < len && s[i] != '=')
			{
				tmp += s[i];
				i++;
			}
			i++;
			if (type != -1 && webContentTag[type] == tmp)
			{
				while (i < len && s[i] != '&')
				{
					content += s[i];
					i++;
				}
				return;
			}
			else
			{
				while (i < len && s[i] != '&')
					i++;
			}
		}
		else
		{
			i++;
		}
	}
}

/**
总函数。调用1部分的getWebAndContext和2部分的solver.UrlUTF8Decode 或
传参数，地址栏字符串s，搜索网站字符串web，搜索关键字字符串content
返回值，结果保存到web和content中。
*/
void getInfo(string s, string &web, string &content)
{
	int type;
	getWebAndContext(s, web, content, type);
	if (type == -1) return;///异常return
	else
	{
		strCoding solver;
		if (!webDecodeType[type])
			content = solver.UrlUTF8Decode(content);
		else
			content = solver.UrlGB2312Decode(content);
	}
}

int selftest()
{
	/**
	https://search.yahoo.com/search;_ylt=AnQD3s591ZlMFxaKx2Ac_jObvZx4?p=%E6%B0%B4%E7%94%B5%E8%B4%B9%E6%B0%B4%E7%94%B5%E8%B4%B9sdf&toggle=1&cop=mss&ei=UTF-8&fr=yfp-t-901&fp=1
	*/
	///使用前先调用init();
	init();

	string s, web, content;
	while (cin >> s)
	{
		getInfo(s, web, content);
		cout << "web:\n" << web << endl;
		cout << "content:\n" << content << endl;
	}
	return 0;
}

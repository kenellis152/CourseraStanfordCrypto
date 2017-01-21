#include <vector>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using std::string;
using std::vector;
using std::cout;
using std::endl;

class cipher
{
    public:
        cipher(string s): ciphertext(s), knowledgestate(s.length()/2, '0'), cipherlength(s.length()){};
        int getLength(){return cipherlength;};
        string getCipher(){return ciphertext;};
        char getKnowledgeState(unsigned int index)
        {
            if(index < knowledgestate.length())
                return knowledgestate[index];
        }
        void setKnowledgeState(char input, int index)
        {
            if(index < cipherlength/2)
                knowledgestate[index]=input;
        }

    private:
        string ciphertext;
        string knowledgestate;//representing what we know about each ASCII character, thus it is half the length of the hex cipher text
        int cipherlength;
};
int hexchartoint(char c)//takes a single hex character from 0-f and converts it to an integer
{
    if(c>='0' && c<='9')
        return c-'0';
    if(c>='a' && c<='f')
        return (c - 'a' + 10);
    if(c>='A' && c<='F')
        return (c-'A' + 10);
    return 0;
}
char hexinttochar(int i)//takes an integer from 0-15 and returns the hex character 0-f
{
    if(i>=0 && i<=9)
        return i + '0';
    if(i>=10 && i<=15)
        return i - 10 + 'a';
    return 0;
}
string hexstringxor(string input1, string input2)//xors two hex strings and returns the xor in hex
{
    string result(input1.length() < input2.length() ? input1.length() : input2.length() , '0');

    for(unsigned int i = 0; i < result.length(); i++)
    {
        int iresult = hexchartoint(input1[i]) ^ hexchartoint(input2[i]);
        result[i]= hexinttochar(iresult);
    }
    return result;
}
string hexstringtoascii(string input)//converts a hex string to ascii
{
    string result;
    for(unsigned int i = 0; i < input.length()/2; i++)
    {
        char a = input[i*2], b = input[i*2+1];
        int intresult = 16*hexchartoint(a) + hexchartoint(b);
        result.push_back(char(intresult));
    }
    return result;
}
string asciistringtohex(string input)
{
    string result;
    for(unsigned int i = 0; i < input.length(); i++)
    {
        int buf=input[i];
        char chara = hexinttochar(buf/16);
        char charb = hexinttochar(buf%16);
        result.push_back(chara);
        result.push_back(charb);
    }
    return result;
}

void analyze(vector<cipher> &ciphers, string &key)
{
    for(int i = 0; i < ciphers.size(); i++)//for each cipher
    {
        for(int j = 0; j < ciphers[i].getCipher().length()/2; j++)//for each pair of hex digits ** j*2 is the index being looked at **
        {
            int lettercount=0;
            int inconclusive=0;
            for(int k = 0; k < ciphers.size(); k++)//for each other cipher
            {
                if(i!=k && key[j*2] == '0'&& key[j*2+1] == '0' && j*2+1 <= ciphers[k].getCipher().length()) //if the ciphers are different and the key at this index is still set to 0
                {
                    //read in the pair of hex digits for each string
                    string abuff(ciphers[i].getCipher(),j*2,2), bbuff(ciphers[k].getCipher(),j*2,2);
                    string xorstring = hexstringxor(abuff, bbuff);
                    int xorint = 16*hexchartoint(xorstring[0]) + hexchartoint(xorstring[1]);
                    if( xorint >= 65 && xorint <= 122 )
                        ++lettercount;
                    for(int m=33; m <= 63; m++)
                        if(xorint == (32 ^ m) )
                            ++inconclusive;

                }
            }
            if( lettercount > ciphers.size()/2 )
            {
                string abuff(ciphers[i].getCipher(),j*2,2);
                string newkey = hexstringxor(abuff, "20");
                key[j*2]=newkey[0];
                key[j*2+1]=newkey[1];
            }
        }
    }
}


int main()
{
    //read in the ciphers into vector ciphers
    std::fstream fin("ciphers.txt");
    string stringbuff;//input buffer
    vector<cipher> ciphers;//stores the ciphers
    unsigned int maxlength=0;
    unsigned int secondlongest;
    while(std::getline(fin, stringbuff))
    {
        cipher cipherbuff(stringbuff);
        ciphers.push_back(cipherbuff);
        cout << "read in cipher of length " << stringbuff.length() << endl;
        if(stringbuff.length() > maxlength)
        {
            secondlongest=maxlength;
            maxlength=stringbuff.length();
        }
    }

    //analyze the ciphers, guessing the positions of spaces and solving the key for positions where I think there is a space
    string key(secondlongest, '0');
    analyze(ciphers, key);

    //print the initial decryptions
    string resultbuff;
    for(int i = 0; i < ciphers.size(); i++)
    {
        resultbuff = hexstringxor(ciphers[i].getCipher(), key);
        cout << "decryption of cipher # " << i << " is: " << hexstringtoascii(resultbuff) << endl<<endl;
    }

    string messageguess, keyguess;
    bool quit = false;
    while(quit==false)
    {
        int selection;
        cout << endl << "enter number of cipher to guess message starting from zero (0 through " << ciphers.size()-1 << ")" << endl;
        //std::cin.ignore();
        std::cin >> selection;
        if(selection >= ciphers.size() || selection < 0)
            return 0;
        cout << "enter guess for message" << endl;

        std::cin.ignore();
        std::getline(std::cin, messageguess);
        cout << endl << endl;

        keyguess = hexstringxor(asciistringtohex(messageguess), ciphers[selection].getCipher());

        for(int i = 0; i < ciphers.size(); i++)
        {
            resultbuff = hexstringxor(ciphers[i].getCipher(), keyguess);
            cout << "decryption of cipher # " << i << " is: " << hexstringtoascii(resultbuff) << endl<<endl;
        }
    }

}

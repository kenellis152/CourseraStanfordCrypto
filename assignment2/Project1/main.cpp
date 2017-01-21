#include "F:\code\cryptopp\osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "F:\code\cryptopp\cryptlib.h"
using CryptoPP::Exception;

#include "F:\code\cryptopp\hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "F:\code\cryptopp\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "F:\code\cryptopp\aes.h"
using CryptoPP::AES;

#include "F:\code\cryptopp\modes.h"
using CryptoPP::ECB_Mode;


using std::string;
using std::vector;
using std::cout;
using std::endl;
using namespace CryptoPP;

vector<byte> EncryptSingleAESBlock(vector<byte> plaintext, vector<byte> keyin);
vector<byte> DecryptSingleAESBlock(vector<byte> cipher, vector<byte> keyin);
vector<byte> CBCEncrypt(vector<byte> input, vector<byte> keyinput, vector<byte> iv= vector<byte>());
vector<byte> CTREncrypt(vector<byte> input, vector<byte> keyinput, vector<byte> iv= vector<byte>());
vector<byte> CBCDecrypt(vector<byte> cipher, vector<byte> keyin);
vector<byte> CTRDecrypt(vector<byte> cipher, vector<byte> keyin);

int hexchartoint(char c);//takes a single hex character from 0-f and converts it to an integer
char hexinttochar(int i);//takes an integer from 0-15 and returns the hex character 0-f
string hexstringtoascii(string input);//converts a hex string to ascii
string oldhexstringtoascii(string input);//converts a hex string to ascii
string asciistringtohex(string input);//converts a string with ascii contents to string with hex contents
string base64toascii(string input);//converts base 64 string to ascii string
string hexstringxor(string input1, string input2);//xors two string with hex contents
vector<byte> bytevectorxor(vector<byte> input1, vector<byte> input2);//xors two vectors with bytes (unsigned char)
void incrementiv(vector<byte> &input);//takes a vector of byte and increments by 1
vector<byte> hexstringtobytevector(string input);//converts a string with hex contents to a vector of bytes
string bytevectortohexstring(vector<byte> input);//converts a vector of bytes to string with hex contents
string bytevectortoasciistring(vector<byte> input);//converts a vector of bytes to a string with ascii contents
vector<byte> asciistringtobytevector(string input);//converts a string with ascii contents to a vector of bytes

int main()
{
	//ciphers 1 and 2 CBC Mode
	//ciphers 3 and 4 encrypted CTR Mode
	string ciphertext1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
	string ciphertext2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
	string ciphertext3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
	string ciphertext4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";

	string key1 = "140b41b22a29beb4061bda66b6747e14";
	string key2 = "140b41b22a29beb4061bda66b6747e14";
	string key3 = "36f18357be4dbd77f050515c73fcf9f2";
	string key4 = "36f18357be4dbd77f050515c73fcf9f2";

	vector<byte> ct1 = hexstringtobytevector(ciphertext1);
	vector<byte> ky1 = hexstringtobytevector(key1);
	vector<byte> ct2 = hexstringtobytevector(ciphertext2);
	vector<byte> ky2 = hexstringtobytevector(key2);
	vector<byte> ct3 = hexstringtobytevector(ciphertext3);
	vector<byte> ky3 = hexstringtobytevector(key3);
	vector<byte> ct4 = hexstringtobytevector(ciphertext4);
	vector<byte> ky4 = hexstringtobytevector(key4);

	string testivstring = "5b68629feb8606f9a6667670b75b38a5";
	string testplaintext = "Our implementation uses rand. IV";
	vector<byte> testiv = hexstringtobytevector(testivstring);
	vector<byte> testinput = asciistringtobytevector(testplaintext);
	vector<byte> testresult = CBCEncrypt(testinput, ky2, testiv);
	cout << "test CBC encryption: " << bytevectortohexstring(testresult) << endl;

	string testivstring2 = "69dda8455c7dd4254bf353b773304eec";
	string testplaintext2 = "CTR mode lets you build a stream cipher from a block cipher.";
	vector<byte> testiv2 = hexstringtobytevector(testivstring2);
	vector<byte> testinput2 = asciistringtobytevector(testplaintext2);
	vector<byte> testresult2 = CTREncrypt(testinput2, ky3, testiv2);
	cout << "test CTR encryption: " << bytevectortohexstring(testresult2) << endl;

	vector<byte> result1 = CBCDecrypt(ct1, ky1);
	cout << "decrypted ciphertext 1 is: " << bytevectortoasciistring(result1) << endl;
	vector<byte> result2 = CBCDecrypt(ct2, ky2);
	cout << "decrypted ciphertext 2 is: " << bytevectortoasciistring(result2) << endl;
	vector<byte> result3 = CTRDecrypt(ct3, ky3);
	cout << "decrypted ciphertext 3 is: " << bytevectortoasciistring(result3) << endl;
	vector<byte> result4 = CTRDecrypt(ct4, ky4);
	cout << "decrypted ciphertext 4 is: " << bytevectortoasciistring(result4) << endl;

	getchar();
	return 0;
}

void incrementiv(vector<byte> &input) {
	int carry = 1;
	for (auto i = input.rbegin(); i != input.rend(); ++i) {
		*i += carry;
		if (*i != 0)
			carry = 0;
	}
	if (carry == 1)
		input[0] = 0;
}

vector<byte> CBCDecrypt(vector<byte> input, vector<byte> keyin)
{
	vector<byte> result;

	if (input.size() % 16 != 0)	{
		cout << "cbc decrypt called with non-full blocks" << endl;
		exit;
	}
	if (keyin.size() != 16)	{
		cout << "cbc decrypt called with incorrect key length" << endl;
		exit;
	}
	
	//grab the iv
	vector<byte> iv;
	std::copy(input.begin(), input.begin() + 16, back_inserter(iv));
		
	//grab the cipher body
	vector<byte> cipherbody;
	std::copy(input.begin() + 16, input.end(), back_inserter(cipherbody));

	result.resize(cipherbody.size());

	int numblocks = (input.size() - 16) / 16;
	vector<byte> thisblock;
	thisblock.resize(16);
	for (int i = 0; i < numblocks; i++){
		std::copy(cipherbody.begin() + i * 16, cipherbody.begin() + (i + 1) * 16, thisblock.begin());
		vector<byte> resultbuff = bytevectorxor(DecryptSingleAESBlock(thisblock, keyin), iv);
		std::copy(resultbuff.begin(), resultbuff.end(), result.begin() + i * 16);
		std::copy(thisblock.begin(), thisblock.end(), iv.begin());
	}

	//strip padding
	int padlength = result[result.size() - 1];
	result.erase(result.end() - padlength, result.end());
	
	return result;
}

vector<byte> CTRDecrypt(vector<byte> input, vector<byte> keyin) {

	if (keyin.size() != 16) {
		cout << "cbc decrypt called with incorrect key length" << endl;
		exit;
	}

	//grab the iv
	vector<byte> iv;
	std::copy(input.begin(), input.begin() + 16, back_inserter(iv));

	//grab the cipher body
	vector<byte> cipherbody;
	std::copy(input.begin() + 16, input.end(), back_inserter(cipherbody));

	//stores the AES encryptions that will be xored against the cipher text
	vector<byte> xorbody;
	xorbody.reserve(cipherbody.size());

	//buffer that stores each AES encryption result
	vector<byte> thisblock;
	thisblock.resize(16);

	int numblocks = (input.size()-16) / 16;
	if ((input.size() % 16) != 0)
		numblocks++;

	for (int i = 0; i < numblocks; i++) {
		thisblock=EncryptSingleAESBlock(iv, keyin);
		xorbody.insert(xorbody.end(), thisblock.begin(), thisblock.end());
		incrementiv(iv);
	}
	
	//trim down xorbody to the length of cipherbody so both are the same length before xor'ing
	xorbody.erase(xorbody.begin() + cipherbody.size(), xorbody.end());

	return bytevectorxor(cipherbody, xorbody);
}

vector<byte> CBCEncrypt(vector<byte> input, vector<byte> keyinput, vector<byte> iv) {
	//generate random iv if no iv provided
	if (iv.size() == 0) {
		AutoSeededRandomPool rnd;
		byte iv[AES::BLOCKSIZE];
		rnd.GenerateBlock(iv, AES::BLOCKSIZE);
	}

	//pad the input
	int padlength = 16 - input.size() % 16;
	for (int i = 0; i < padlength; i++)
		input.push_back(padlength);
	
	//encrypt
	vector<byte> xorresult;//buffer to hold xor of iv and message block and output of AES
	vector<byte> thisblock; //buffer to hold current message block
	vector<byte> result = iv;
	thisblock.resize(AES::BLOCKSIZE);
	int numblocks = input.size() / 16;
	for (int i = 0; i < numblocks; i++) {
		std::copy(input.begin() + i * 16, input.begin() + (1 + i) * 16, thisblock.begin());
		xorresult = bytevectorxor(iv, thisblock);
		iv = EncryptSingleAESBlock(xorresult, keyinput);
		std::copy(iv.begin(), iv.end(), back_inserter(result));
	}
		
	return result;
}
vector<byte> CTREncrypt(vector<byte> input, vector<byte> keyinput, vector<byte> iv) {
	//generate random iv if no iv provided
	if (iv.size() == 0) {
		AutoSeededRandomPool rnd;
		byte iv[AES::BLOCKSIZE];
		rnd.GenerateBlock(iv, AES::BLOCKSIZE);
	}

	//get blocksize
	int numblocks = (input.size()) / 16;
	if ((input.size() % 16) != 0)
		numblocks++;

	//get encryption that input is xored against
	vector<byte> result = iv;
	vector<byte> xoroperand, encryption;
	for (int i = 0; i < numblocks; i++) {
		encryption = EncryptSingleAESBlock(iv, keyinput);
		incrementiv(iv);
		std::copy(encryption.begin(), encryption.end(), back_inserter(xoroperand));
	}

	//trim the xoroperand to same length as input
	int difference = xoroperand.size() - input.size();
	if (difference > 0) {
		xoroperand.erase(xoroperand.end() - difference, xoroperand.end());
	}
	
	//initialize result vector to iv, then add on the xor result
	xoroperand = bytevectorxor(input, xoroperand);
	std::copy(xoroperand.begin(), xoroperand.end(), back_inserter(result));
	return result;
}

vector<byte> EncryptSingleAESBlock(vector<byte> plaintext, vector<byte> keyin) {
	byte key[AES::DEFAULT_KEYLENGTH];
	for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
		key[i] = keyin[i];

	ECB_Mode< AES >::Encryption e;
	e.SetKey((byte*)key, AES::DEFAULT_KEYLENGTH);

	string resultbuffer; //store the encryption in a hexstring
	StringSource(bytevectortoasciistring(plaintext), true,
		new StreamTransformationFilter(e,
			new StringSink(resultbuffer), CryptoPP::BlockPaddingSchemeDef::NO_PADDING
		) // StreamTransformationFilter
	); // StringSource

	if (resultbuffer.length() > 16)
		resultbuffer = resultbuffer.substr(0, 16);

	return asciistringtobytevector(resultbuffer);
}

vector<byte> DecryptSingleAESBlock(vector<byte> cipherin, vector<byte> keyin) {
	string result;
	result.reserve(cipherin.size());

	byte key[AES::DEFAULT_KEYLENGTH];
	for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
		key[i] = keyin[i];
	string cipher = bytevectortoasciistring(cipherin);

	ECB_Mode< AES >::Decryption d;
	d.SetKey((byte*)key, AES::DEFAULT_KEYLENGTH);

	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true,
		new StreamTransformationFilter(d,
			new StringSink(result), CryptoPP::BlockPaddingSchemeDef::NO_PADDING
		)
		// StreamTransformationFilter
	); // StringSource

	if (result.length() > 32){
		result = result.substr(0, 32);
		cout << "warning: DecryptSingleAesBlock called with input size greater than one block" << endl;
	}
		
	return asciistringtobytevector(result);
}

int hexchartoint(char c)//takes a single hex character from 0-f and converts it to an integer
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return 0;
}
char hexinttochar(int i)//takes an integer from 0-15 and returns the hex character 0-f
{
	if (i >= 0 && i <= 9)
		return i + '0';
	if (i >= 10 && i <= 15)
		return i - 10 + 'a';
	return 0;
}

string oldhexstringtoascii(string input)//converts a hex string to ascii
{
	string result;
	for (unsigned int i = 0; i < input.length() / 2; i++)
	{
		char a = input[i * 2], b = input[i * 2 + 1];
		int intresult = 16 * hexchartoint(a) + hexchartoint(b);
		result.push_back(char(intresult));
	}
	return result;
}

string hexstringtoascii(string input)
{
	string result;
	StringSource(input, true,
		new HexDecoder(
			new StringSink(result)
		) // HexEncoder
	); // StringSource
	return result;
}
string base64toascii(string input)
{
	string result;
	StringSource(input, true,
		new BaseN_Decoder(
			new StringSink(result)
		) // HexEncoder
	); // StringSource
	return result;
}

string asciistringtohex(string input)
{
	string result;
	StringSource(input, true,
		new HexEncoder(
			new StringSink(result)
		) // HexEncoder
	); // StringSource
	return result;
}

string hexstringxor(string input1, string input2)//xors two hex strings and returns the xor in hex
{
	string result(input1.length() < input2.length() ? input1.length() : input2.length(), '0');

	for (unsigned int i = 0; i < result.length(); i++)
	{
		int iresult = hexchartoint(input1[i]) ^ hexchartoint(input2[i]);
		result[i] = hexinttochar(iresult);
	}
	return result;
}

vector<byte> bytevectorxor(vector<byte> input1, vector<byte> input2) {
	//larger stores which vector is larger: 1 for input2 and 2 for input2, 0 for equal length
	int larger, largerlength, smallerlength;
	if (input1.size() == input2.size()) {
		larger = 0;
		largerlength = smallerlength = input1.size();
	}
	else if (input1.size() > input2.size()) {
		larger = 1;
		largerlength = input1.size();
		smallerlength = input2.size();
	}
	else {
		larger = 2;
		largerlength = input2.size();
		smallerlength = input1.size();
	}

	if (larger)
		cout << "warning: byte vector xor called with inputs of different length" << endl;

	vector<byte> result = (larger == 2) ? input2 : input1;

	for (int i = 0; i < smallerlength; i++)
		result[i] = (input1[i] ^ input2[i]);
	
	return result;
}

vector<byte> hexstringtobytevector(string input) {
	vector<byte> result;
	result.reserve(input.size() / 2);
	for (int i = 0; i < input.length()/2; i++)
		result.push_back( hexchartoint(input[i*2])*16 + hexchartoint(input[i*2+1]) );
	return result;
}

string bytevectortohexstring(vector<byte> input) {
	string result;
	result.reserve(input.size() * 2);
	for (auto i : input){
		result.push_back(hexinttochar(i / 16));
		result.push_back(hexinttochar(i % 16));
	}
	return result;
}

string bytevectortoasciistring(vector<byte> input) {
	string result;
	result.reserve(input.size());
	for (auto i : input)
		result.push_back(i);

	return result;
}
vector<byte> asciistringtobytevector(string input) {
	vector<byte> result;
	result.reserve(input.length());
	for (auto i : input)
		result.push_back((unsigned char)i);
	return result;
}
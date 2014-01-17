// Author:  Iordanis Fostiropoulos, ifostiropoul2011@my.fit.edu
// Course:  CSE 3120
// Project: CryptoMax

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <cstdlib>
#include <iostream>
#include <string> 
#include <windows.h>
#include <Commdlg.h>
#include <fstream>

typedef char BYTE_;

// the crendentials structure storing the key
struct credentials {	
	BYTE_* key;
	int keyLength;

};

using namespace std;

// INTERNAL C++ PROCEDURES
char* getKeySaveLocation(const wchar_t* filter);
char* getFileLocation(const wchar_t* filter);
bool printHeader();
int saveEncryptionKey(credentials* key);
credentials* getKeyword();
credentials* getFileInputKey();

extern "C" {

	// external ASM procedures:

	// displays error if filename is not right.
	int offsetFileBytes(char* fileName, BYTE_* keyword, int keywordLength, bool isNegativeOffset);

	// displays error if filename is not right.
	int saveKey(char* file,credentials* key);

	// displays error if filename is not right.
	credentials* openEncryptionKey(char* fileName);

	// generate random key of int, key is as specified
	credentials* generateRandomKey();

	// generate key from mouse
	credentials* generateMouseKey();

	// C++ Procedures:

	// remove file - redefined
	int remove (const char*  filename );
	
}
	
/*
Key description,
max length 255
Each element has the value of 0-255
Each element rotates the word by that number
key files have the .key ending
*/
int main()
{
	// Print header art
	printHeader();
	unsigned char cmd;
	string input;
	
	// display header
	cout << "Do you want to encrypt or decrypt a file?\n";
	cout << (char)9 << "1: Encrypt\n";
	cout << (char)9 << "2: Decrypt\n";
	cout  << ">> ";
	cin >> cmd;

	// Get the encoded/decoded file
	char* filename=getFileLocation(L"All\0*.*\0");

	if(cmd=='1'){
		//menu
		cout << "Encrypter Started\n\n";
		cout << "What method do you want to use to create a key?\n";
		cout << (char)9 << "1: Console Input (up to 255 byte)\n";		
		cout << (char)9 << "2: Key file (255 byte)\n";
		cout << (char)9 << "3: Randomized key (255 byte)\n";
		cout << (char)9 << "4: Mouse Randomized key (255 byte)\n";
		cout  << ">> ";
		cin >> cmd;
		credentials* tmpCreds;
		
		switch (cmd)
		{
			case '1':
				tmpCreds=getKeyword();
				break;

			case '2':
				tmpCreds = getFileInputKey();
				break;

			case '3':
				tmpCreds=generateRandomKey();
				break;

			default:
				cout << "Please move your mouse rapidly to generate a good key.\n";
				tmpCreds=generateMouseKey();
				break;
		}

		cout << "In what form do you want to output the key?\n";
		cout << (char)9 << "1: Console Output\n";		
		cout << (char)9 << "2: Key file\n";
		cout  << ">> ";
		cin >> cmd;
		switch (cmd)
		{
			case '1':
				cout << "Key is in HEX values. Use an ASCII table to convert.\n";
				for (int i = 0; i < tmpCreds->keyLength; i++)
				{
					printf("%02X ", (unsigned char) tmpCreds->key[i]);

				}
				cout << endl;
				break;
			default:
				saveEncryptionKey(tmpCreds);
				break;
		}
		// encoding
		if(!offsetFileBytes(filename,tmpCreds->key,tmpCreds->keyLength,false)){
			cout << "File is Invalid";
			return 0;
		}
		cout << "The original file has been encrypted.\n"
			 << "NOTE: Please keep the key safe if you want to reverse the process \n";


	}else{

		cout << "Decrypter Started\n\n";
		cout << "What method do you want to use to input the key?\n";
		cout << (char)9 << "1: Console Input\n";
		cout << (char)9 << "2: Key file (255 byte)\n";
		cout  << ">> ";
		cin >> cmd;
		credentials* tmpCreds;

		switch (cmd)
		{
			case '1':
				tmpCreds=getKeyword();
				break;

			default:			
				tmpCreds = getFileInputKey();
				break;
		}
		// decoding
		offsetFileBytes(filename,tmpCreds->key,tmpCreds->keyLength,true);
		cout << "The original file has been decrypted.\n"
			 << "! NOTE: If the wrong key was used to decrypt the file,\n"
			 << "encrypt it with the same key to reverse the process \n";
	}
	     
	return 1;
}

// prints the header of the file, ascii art 
// stored in HeaderArt.art
bool printHeader(){
	 string line;
	  ifstream headerFile ("HeaderArt.art");
	  if (headerFile.is_open())
	  {
		while ( getline (headerFile,line) )
		{
		  std::cout << line << endl;
		}
		std::cout << endl << endl;
		headerFile.close();
		return true;
	  }

	  else 
		  return false;
}
// reads the save location of the encryption key and saves it
int saveEncryptionKey(credentials* key){

		char* fileLocation = getKeySaveLocation(L"Key File\0*.KEY\0All\0*.*\0");
		saveKey(fileLocation,key);
		return 0;
}

// reads the location of the file key and opens it
credentials* getFileInputKey(){

		char* fileLocation = getFileLocation(L"Key File\0*.KEY\0All\0*.*\0");
		return openEncryptionKey(fileLocation);
}

// reads the keyword from the keyboard
credentials* getKeyword(){

	string input;
	std::cin >> input;
	char *inputArray = new char[input.length()+1];
	strcpy(inputArray, input.c_str());

	for (int i = 0; i < input.length(); i++){
		inputArray[i]%=256;
	}

	credentials* tmp=(credentials *) malloc(sizeof(credentials));

	tmp->key=inputArray;
	tmp->keyLength=input.length();
	return tmp;
}



// gets the file location using an open file dialogue 
char* getFileLocation(const wchar_t* filter){
	
	OPENFILENAME ofn;
	wchar_t szFile[1024];
	HWND hwnd=NULL;
	HANDLE hf;



	// Display the Open dialog box. 
	do{

		// Initialize OPENFILENAME
		ZeroMemory(&ofn, sizeof(ofn));
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = hwnd;
		ofn.lpstrFile = szFile;
		//
		// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
		// use the contents of szFile to initialize itself.
		//
		ofn.lpstrFile[0] = '\0';
		ofn.nMaxFile = sizeof(szFile);
		ofn.lpstrFilter = filter;
		ofn.nFilterIndex = 1;
		ofn.lpstrFileTitle = NULL;
		ofn.nMaxFileTitle = 0;
		ofn.lpstrInitialDir = NULL;
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	}while (!GetOpenFileName(&ofn));
	
	

	char* fileLocation = new char[wcslen(szFile) + 1];
	//null terminate the string
	fileLocation[wcslen(szFile)]=0;
	wcstombs( fileLocation, szFile, wcslen(szFile) );

	return fileLocation;

}


// reads the location of the item to save 
char* getKeySaveLocation(const wchar_t* filter){
	
	OPENFILENAME ofn;
	wchar_t szFile[1024];

	HWND hwnd=NULL;
	HANDLE hf;
	// Display the Open dialog box. 
	do{
		// Initialize OPENFILENAME
		ZeroMemory(&ofn, sizeof(ofn));
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = hwnd;
		ofn.lpstrFile = szFile;
		//
		// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
		// use the contents of szFile to initialize itself.
		//
		ofn.lpstrFile[0] = '\0';
		ofn.nMaxFile = sizeof(szFile);
		ofn.lpstrFilter = filter;
		ofn.nFilterIndex = 1;
		ofn.lpstrFileTitle = NULL;
		ofn.nMaxFileTitle = 0;
		ofn.lpstrInitialDir = NULL;
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	}while (!GetSaveFileName(&ofn));

	char* fileLocation = new char[wcslen(szFile) + 1];
	//null terminate the string
	fileLocation[wcslen(szFile)]=0;
	wcstombs( fileLocation, szFile, wcslen(szFile) );

	return fileLocation;

}
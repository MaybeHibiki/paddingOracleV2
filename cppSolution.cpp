
#include <iostream>
#include <vector>
using namespace std;

vector<vector<int>> cipherText;  //We assume that ciphertext is given in blocks as C0(IV) C1, C2, C3 ... Ci-1, Ci

// return 1 if padding is valid and 0 otherwise.
bool PO(vector<int> block1, vector<int> block2)
{
    return 1;
}

//pre: given the last block of ciphertext (Ci) and its previous block (Cp)
//post: return the padding length of the block.
int findPadLength (vector<int> Ci, vector<int> Cp){
    vector<int> delta(Cp); //A copy of the Cp 
    for(short i = 0; i<16; i++) //we traversing the block byte by byte using a short pointer.
    {
        delta[i] = delta[i] ^ 0xff; //Flip every byte. Note that a flipped byte is never the same as it was unflipped.
        if(!PO(delta, Ci))           //in this way, when we reach the byte that was supposed to be part of the padding, PO would rejects 
        return 16-i;                //When it rejects, we return the padding length. 
    }
}

//Pre: given the last block of ciphertext (Ci) and its previous block (Cp) and padding length 
//Post: return the plaintext block (Mi)
vector<int> decryptBlock (vector<int> Ci, vector<int> Cp, int padLength){
        vector<int> plainText(16,0);
        int c = 0; 
        for(int i = 15; i> 15-padLength;i--){ //We know so far that plaintext block contains padLength bytes of padding.
            plainText[i] = padLength;
        }
        for(int i = 15-padLength; i>=0; i--)  //we know that 15-padLength is the first index that has a message byte.
        {                                     //and we want to decipher all the message bytes starting from there to the beginning
        vector<int> temp(Cp);   //a copy of the previous block Cp
        vector<int> delta(plainText);    //delta1 that Cp is going to XOR with and gives all 0 in the right most b+c bytes. Where b is the padding length and c is the counter of message bytes we have discovered so far
        vector<int> delta2(16,0);        //delta2 XOR with (Cp XOR delta1) set the right most b+c bytes the value of b+c+1
            for(int j = i+1; j<=15;j++){
                delta2[j] = padLength + c + 1;
            }
            //Construct the Cp XOR delta1 XOR delta2
            for(int j = 0; j<=15; j++){
                temp[j] ^= delta[j] ^ delta2[j];
            }
            //Now we are ready for our trial & error process to find the message byte at the right most b+c+1 position.
            for(int j = 0; j<256; j++){ 
                delta[i] = j;
                if(PO(temp,Ci)){    //If PO accepts, then we proceed to find the message byte
                    plainText[i] = (padLength + c + 1 ) ^ j;
                    c++; //increase the c, indicating the number of message bytes we have found so far.
                    break;
                }
            }
        }
        return plainText;
    }



//Pre: Given cipherText
//Post: Return plaintext in blocks 
vector<vector <int>> attack (vector<vector<int>> cipherText){
    vector<vector<int>> plainText(cipherText.size()-1); //Excluding IV 
    for(int i = cipherText.size()-1; i>0; i--){ //we assume C0 is IV
        if(PO(cipherText[i-1],cipherText[i])){ //if PO accepts, then we are in the case of Ci-1 and Ci. Which Ci is the last block and has a valid padding. In this case we find the padLength and proceed.
            int padLength = findPadLength(cipherText[i-1],cipherText[i]);
            plainText[i-1] = decryptBlock(cipherText[i-1],cipherText[i],padLength);
        }
        else{//If PO rejects, Ci doesn't have a valid padding, indicating that it's a full message block. So padLength is 0;
            plainText[i-1] = decryptBlock(cipherText[i-1],cipherText[i],0);
        }
    }
    return plainText;
    
}

int main(){
    cout<<"Hello world";
    return 0;
}
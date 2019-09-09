/*
Simplified Data Encryption Standard (S-DES) in javascript
Developed by Lachlan Woods - 2019
*/

var permutation10 = [3,5,2,7,4,10,1,9,8,6];
var permutation8 = [6,3,7,4,8,5,10,9];
var permutation4 = [2,4,3,1];
var initialPermutation = [2,6,3,1,4,8,5,7];
var inverseInitialPermutation = [4,1,3,5,7,2,8,6];
var expandPermute = [4,1,2,3,2,3,4,1];
var substitution0 = [[[0,1], [0,0], [1,1], [1,0]],
                     [[1,1], [1,0], [0,1], [0,0]],
                     [[0,0], [1,0], [0,1], [1,1]],
                     [[1,1], [0,1], [1,1], [1,0]]];
var substitution1 = [[[0,0], [0,1], [1,0], [1,1]],
                     [[1,0], [0,0], [0,1], [1,1]],
                     [[1,1], [0,0], [0,1], [0,0]],
                     [[1,0], [0,1], [0,0], [1,1]]];

var roundKey1;
var roundKey2;
var ciphertext;

//generates an array of random bits
//this is used to generate a random shared key, and some example plaintext / ciphertext
function GenerateRandomBits(length){
  bitArray = new Array(length); //create an array of size length
  for(var i = 0; i < length; i++){ //loop 10 times (since we use a 10 bit key)
    bitArray[i] = (Math.random() > 0.5) ? 1 : 0; //generate a random bit (1 or 0)
  }
  return bitArray;
}

/**********************************************************************************************************
Round Key Generation
***********************************************************************************************************/

//Generates our two 8 bit round keys. This calls all functions in the correct order
//to generate our round keys (see SDES flowchart for details)
function RoundKeyGeneration(key){
  var p10Result = Permutation(key, permutation10);
  var shift1 = LeftBitShift(p10Result.slice(0,5));
  var shift2 = LeftBitShift(p10Result.slice(5, p10Result.length));
  roundKey1 = Permutation(shift1.concat(shift2), permutation8);
  console.log("Round key 1: " + roundKey1);
  var shift3 = LeftBitShift(LeftBitShift(shift1));
  var shift4 = LeftBitShift(LeftBitShift(shift2));
  roundKey2 = Permutation(shift3.concat(shift4), permutation8);
  console.log("Round key 2: " + roundKey2);
}

/**********************************************************************************************************
Encyption / decryption functions
***********************************************************************************************************/

//calls all the stages of encryption in order, then swaps the round keys to decrypt the ciphertext
function Encrypt(plainText, sharedKey){
  console.log("Input plaintext: " + plainText);
  RoundKeyGeneration(sharedKey); //generate our two round keys (stored as global variables)

  console.log("-----------------------Encrypting-----------------------");
  var ipResult = Permutation(plainText, initialPermutation); //perform the initial permutation stage
  var block1Result = EncryptionBlock(ipResult, roundKey1); //the result of the first block of encryption
  switchBits = block1Result.slice(4, block1Result.length).concat(block1Result.slice(0, 4));//swaps the bits returned from the first block
  block2Result = EncryptionBlock(switchBits, roundKey2); //perform the second block
  ciphertext = Permutation(block2Result, inverseInitialPermutation);
  console.log("Ciphertext: " + ciphertext);

  console.log("-----------------------Decrypting-----------------------");
  var ipResult = Permutation(ciphertext, initialPermutation); //perform the initial permutation stage
  var block1Result = EncryptionBlock(ipResult, roundKey2); //the result of the first block of encryption
  switchBits = block1Result.slice(4, block1Result.length).concat(block1Result.slice(0, 4));//swaps the bits returned from the first block
  block2Result = EncryptionBlock(switchBits, roundKey1); //perform the second block
  var plaintext = Permutation(block2Result, inverseInitialPermutation);
  console.log("Decrypted plaintext: " + plaintext);
}

//performs a single block for encryption
function EncryptionBlock(input, roundKey){
  var leftHalf = input.slice(0,4);
  var rightHalf = input.slice(4, input.length);
  var expandedPermutation = Permutation(rightHalf, expandPermute);
  var xor = XOR(expandedPermutation, roundKey); //perform an xor with our round key
  var sub0 = SBox(xor.slice(0,4), substitution0); //apply SBox on left half of xor
  var sub1 = SBox(xor.slice(4, xor.length), substitution1); //apply SBox on right half of xor
  var p4Result = Permutation(sub0.concat(sub1), permutation4);
  var xor2 = XOR(leftHalf, p4Result);
  var blockResult = xor2.concat(rightHalf);
  console.log("Block result: " + blockResult);
  return blockResult;
}

/**********************************************************************************************************
Bit manipulation functions
***********************************************************************************************************/

//permutate the bits (i.e move them around) in the key using the permutation table.
//outputs a value with the same length as permutationTable (e.g 10 bits for P10, 8 for P8)
function Permutation(input, permutationTable){
  var permutatedBits = new Array(permutationTable.length);
  for(var i=0; i<permutationTable.length; i++){
    permutatedBits[i] = input[(permutationTable[i]) - 1];
  }
  return permutatedBits;
}

//perform a left bitwise shift. The leftmost bit will wrap around
function LeftBitShift(input){
  input.push(input.shift());
  return input;
}

//perform an xor operation over the bits in the input arrays. These should be the same length
function XOR(input1, input2){
  for(var i=0; i<input1.length; i++){
    if((input1[i] == 0 && input2[i] == 1) || (input1[i] == 1 && input2[i] == 0)){
      input1[i] = 1;
    }else{
      input1[i] = 0;
    }
  }
  return input1;
}

//takes 4 bits input, and returns a two bit outputs. Output is looked up in the substitution0 and substitution1 tables
//bits 1 and 4 of input specifies the row to get the output from
//bits 2 and 3 of input specifies the column to get the output from
function SBox(input, outputTable){
  var row = BinaryArrayToInt([input[0], input[3]]);
  var column = BinaryArrayToInt([input[1], input[2]]);
  return outputTable[row][column];
}


/**********************************************************************************************************
Helper functions - These are not part of the main SDES algorithm. They were just used to overcome some javascript issues.
***********************************************************************************************************/

//takes an array of 1's and 0's and convert this to an integer. I could not find a better way to do this, but
//im sure this is a better way.
function BinaryArrayToInt(binary){
  var str = binary.join(''); //convert the array into a string of 1's and 0's
  return parseInt(str, 2 ); //convert the string of bits into an int and return it
}

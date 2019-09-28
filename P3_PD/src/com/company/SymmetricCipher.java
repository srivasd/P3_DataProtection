package com.company;

import java.util.ArrayList;
import java.util.List;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	
	// Initialization Vector (fixed)
	
	byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public void SymmetricCipher() {
		byteKey = null;
		s = null;
		d = null;
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

		s = new SymmetricEncryption(byteKey);

		byte[] ciphertext = null;

		// Generate the plaintext with padding
			int inputLength = input.length;
			int lastBlockLength = inputLength % 16;
			int paddingLength = 16 - lastBlockLength;

			byte[] newInput = new byte[inputLength + paddingLength];
			String paddingLengthByteString = Integer.toHexString(paddingLength);
			byte paddingByte =  (byte) paddingLength;
			for (int i = 0; i < newInput.length; i ++) {
				if(i >= inputLength) {
					newInput[i] = paddingByte;
				} else {
					newInput[i] = input[i];
				}
			}

			//Fill the arraylist with blocks
			List<byte[]> blocks = new ArrayList<byte[]>();
			byte[] block = new byte[16];
			int n = 0;
			for (int j=0; j < newInput.length; j++) {
				if (n < 15) {
					block[n] = newInput[j];
					n++;
				} else if(n == 15){
					block[n] = newInput[j];
					blocks.add(block);
					n = 0;
					block = new byte[16];
				}
			}

			//XOR and encryptblock

			//XOR iv and encryptblock
			byte[] result = new byte[blocks.size() * 16];
			byte[] resultAux = s.encryptBlock(XORBytes(blocks.get(0), iv));
			System.arraycopy(resultAux, 0, result, 0, 16);


			//XOR and encryptblock (all blocks)
			for(int z=1; z < blocks.size(); z++) {
				byte[] resultAux2 = s.encryptBlock(XORBytes(blocks.get(z), resultAux));
				for(int b=0; b < 16; b++){
					result[b + 16*z] = resultAux2[b];
				}
				for (int j=0; j < resultAux.length; j++) {
					resultAux[j] = resultAux2[j];
				}
			}
	
			// Generate the ciphertext
			ciphertext = result;
		
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {

		d = new SymmetricEncryption(byteKey);
		byte [] finalplaintext = null;
		List<byte[]> blocks = new ArrayList<byte[]>();
		byte[] block = new byte[16];
		int n = 0;

		//Fill the arraylist with blocks
		for (int j=0; j < input.length; j++) {
			if (n < 15) {
				block[n] = input[j];
				n++;
			} else if(n == 15){
				block[n] = input[j];
				blocks.add(block);
				n = 0;
				block = new byte[16];
			}
		}

		//Decryptblock and XOR

		//Decryptblock and XOR iv
		byte[] result = new byte[blocks.size() * 16];
		byte[] resultAux = XORBytes(d.decryptBlock(blocks.get(0)), iv);
		System.arraycopy(resultAux, 0, result, 0, 16);

		//Decryptblock and XOR blocks
		for(int z=1; z < blocks.size() ; z++) {
			byte[] resultAux2 = XORBytes(d.decryptBlock(blocks.get(z)), blocks.get(z-1));
			for(int b=0; b < 16; b++){
				result[b + 16*z] = resultAux2[b];
			}
		}

        int paddingLength = 0;
        paddingLength = result[result.length - 1];

		//Generate the finalplaintext
		int finalplaintextLength = result.length - paddingLength;
		finalplaintext = new byte[finalplaintextLength];
		for (int y=0; y < finalplaintextLength; y++) {
			finalplaintext[y] = result[y];
		}

		return finalplaintext;
	}

	public byte[] XORBytes (byte[] input, byte[]aux) {
		byte[] xorResult = new byte[16];

		for (int i=0; i < input.length; i++) {
			xorResult[i] = (byte) (input[i] ^ aux[i]);
		}

		return xorResult;

	}
}



package des_server2;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * @author Robert
 *
 */
public class Des_Server2 extends Applet implements ds2Interface {
	
	//creation of SIO
	public Shareable getShareableInterfaceObject (AID client_aid, byte parameter){
		return this;
	}
	
	// instance variables declaration
	private byte[] tempValue = new byte[4];
	private byte[] tempsign = new byte[8];
	private byte[] tmp = new byte [18];
	private byte[] balance2 = new byte[]{ (byte)0xe00, 0x4f, (byte)0xd0, (byte) 0x00};
	private byte[] tempData;
	private short i;
	private short overflow;
	private byte [] Key8 = {(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x04,
			(byte)0x05,(byte)0x06,(byte)0x07,(byte)0x08};
	private byte[] sign = new byte[8];
	private DESKey keyDes;
	private Signature mac;
	/* change this based on the key used
	 * LENGTH_DES -> 8 byte
	 * LENGTH_DES3_2KEY -> 16 byte 
	 * LENGTH_DES3_3KEY -> 24 byte 
	 */ 
	private static final short keyLength = KeyBuilder.LENGTH_DES; 
	
	/* change this based on the key used
	 * TYPE_DES 
	 * TYPE_AES
	 */ 
	private static final byte keyType = KeyBuilder.TYPE_DES; 
	/**
	 * install method
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new Des_Server2(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	
	private Des_Server2(byte[] bArray, short bOffset, byte bLength){
		keyDes = (DESKey) KeyBuilder.buildKey(keyType, keyLength, false);
		keyDes.setKey(Key8, (short) 0);
		mac = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, true);
		register();
	} // end of the constructor
	
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case des_server2.Util.GET_VALUE:    getValue(apdu, buf); return;
		case des_server2.Util.DEBIT:	    debit(apdu,buf); 	 return;
		case des_server2.Util.CREDIT:   	credit(apdu,buf);    return;
		case des_server2.Util.LIMITED_CREDIT: limitedCredit(apdu,buf); return;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	public void credit(APDU apdu, byte[] buffer) {
		//check lenght of C-APDU
		if((byte)buffer[ISO7816.OFFSET_LC]!=5)
			ISOException.throwIt(des_server2.Util.LENGTH_ERROR);
		
		//receive data
		//data is read into apdu buffer
		//at offset ISO7816.OFFSET_CDATA
		byte read_count = (byte)(apdu.setIncomingAndReceive());
		
		// store data in buffer in tempData 
		// N.B the terminal sends a 4 byte array lsb first 
		// they are then added in reverse order in tempData
		tempData = new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+3],(byte) buffer[ISO7816.OFFSET_CDATA+2], (byte) buffer[ISO7816.OFFSET_CDATA+1], (byte) buffer[ISO7816.OFFSET_CDATA] };
		
		//sum of arrays without overflow
		overflow = (byte) 0x00;
		for (i=0;i<balance2.length;i++){
		    balance2[i]=(byte) (balance2[i]+tempData[i]+overflow);
		}
		//send response in buffer
		short le = apdu.setOutgoing();
		apdu.setOutgoingLength((byte)4);
		apdu.sendBytesLong(balance2, (short)0, (short) balance2.length);
	}

	public void debit(APDU apdu, byte[] buffer) {
		// check lenght of C-APDU
		if((byte)buffer[ISO7816.OFFSET_LC]!=5)
			ISOException.throwIt(des_server2.Util.LENGTH_ERROR);
		
		//receive data
		//data is read into apdu buffer
		//at offset ISO7816.OFFSET_CDATA
		byte read_count = (byte)(apdu.setIncomingAndReceive());
		
		// store data in buffer in tempData 
		// N.B the terminal sends a 4 byte array lsb first 
		// they are then added in reverse order in tempData
		tempData = new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+3],(byte) buffer[ISO7816.OFFSET_CDATA+2], (byte) buffer[ISO7816.OFFSET_CDATA+1], (byte) buffer[ISO7816.OFFSET_CDATA] };
		
		//compare tempData with minimum balance
		
		//subtraction of arrays
		for (i=0;i<balance2.length;i++){
		    balance2[i]=(byte) (balance2[i]-tempData[i]);
		}
		// send response in buffer
		short le = apdu.setOutgoing();
		apdu.setOutgoingLength((byte)4);
		apdu.sendBytesLong(balance2, (short)0, (short) balance2.length);
	}

	public void getValue(APDU apdu, byte[] buffer) throws CryptoException {

//		byte[] buf = apdu.getBuffer();
		//check lenght of C-APDU
		if((byte)buffer[ISO7816.OFFSET_LC]!=1)
			// LENGTH_ERROR
			ISOException.throwIt(des_server2.Util.LENGTH_ERROR);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) balance2.length);
		apdu.sendBytesLong(balance2, (short)0, (short) balance2.length);

	}
	public void limitedCredit (APDU apdu, byte[] buffer){
		//		 TODO
	}

	/**
	 * receives command from buffer
	 * and returns command in buffer
	 */
	public void getValue2(APDU apdu, short dataOffset, short dataLength)throws CryptoException  {
		byte[] buf = apdu.getBuffer();

		tempData = new byte[1];
		// copy buffer in temporary variables	
		tempData[0] = (byte)buf[0];
		//tempData = subByteArray(buf, (short)0 , (short)0);
		tempsign = subByteArray(buf, (short)1 , (short)8);
		
		
		/* 1. Verify signature of data*/
		try{
			mac.init(keyDes, Signature.MODE_VERIFY);
			boolean outcome = mac.verify(buf, (short)(0), (short) 1, buf, (short) 1,(short)8);
			//		if (outcome!=true)
			{
			//	ISOException.throwIt((short)0x54);
			}
			}catch(NullPointerException e) {
		        ISOException.throwIt((short)0x1800);}
		     catch(ArrayIndexOutOfBoundsException e) {
		        ISOException.throwIt((short)0x2801);}
		     catch(CryptoException e) {
		        ISOException.throwIt((short)(0x0000+e.getReason()));}
	
				// calculate sign
//		     	tempsign = calculateMac(tempData, (short)0, (short) tempData.length);
//			
//				/* 3. Build return array in buffer */
//				short len1 = Util.arrayCopy(tempData, (byte)0, tmp, (short) 0, (short) (tempData.length));
//				short len2 = Util.arrayCopy(tempsign, (byte)0, tmp, (short)len1, (short) (tempsign.length));
//				Util.arrayCopy(tmp,(short) 0, buf, (short)9, (short)len2);		     
		     
		/* 2. Calcuate new signature on value file*/
		    tempsign = calculateMac(balance2, (short)0, (short) balance2.length);
//		try{
//			// calculate sign
//			sign = calculateMac(balance2, (short)0, (short) balance2.length);
//			}catch(NullPointerException e) {
//		        ISOException.throwIt((short)0x7800);}
//		     catch(ArrayIndexOutOfBoundsException e) {
//		        ISOException.throwIt((short)0x6801);}
//		     catch(CryptoException e) {
//		        ISOException.throwIt((short)(0x6810+e.getReason()));}
//		
//		/* 3. Build return array in buffer */
		short len1 = Util.arrayCopy(balance2, (byte)0, tmp, (short) 0, (short) (balance2.length));
		short len2 = Util.arrayCopy(tempsign, (byte)0, tmp, (short)len1, (short) (tempsign.length));
		Util.arrayCopy(tmp,(short) 0, buf, (short)0, (short)len2);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) balance2.length);
		apdu.sendBytesLong(buf, (short)0, (short)balance2.length);
		
	}
	
	public void credit2(APDU apdu, short dataOffset, short dataLength)throws CryptoException  {
		byte[] buf = apdu.getBuffer();

		tempData = new byte[5];
		// copy buffer in temporary variables	
		tempData = subByteArray(buf, (short)0 , (short)4);
		tempsign = subByteArray(buf, (short)5 , (short)12);
		
		
		/* 1. Verify signature of data*/
		try{
			mac.init(keyDes, Signature.MODE_VERIFY);
			boolean outcome = mac.verify(tempData, (short)(0), (short) tempData.length, tempsign, (short) 8,(short)tempsign.length);
			//		if (outcome!=true)
			{
			//	ISOException.throwIt((short)0x54);
			}
			}catch(NullPointerException e) {
		        ISOException.throwIt((short)0x1800);}
		     catch(ArrayIndexOutOfBoundsException e) {
		        ISOException.throwIt((short)0x2801);}
		     catch(CryptoException e) {
		        ISOException.throwIt((short)(0x0000+e.getReason()));
		     }
		     /** begin credit transaction **/
		     	//	store data in buffer in tempData 
				// N.B the terminal sends a 4 byte array lsb first 
				// they are then added in reverse order in tempData
				tempValue = new byte[]{(byte) buf[ISO7816.OFFSET_CDATA+4],(byte) buf[ISO7816.OFFSET_CDATA+3], (byte) buf[ISO7816.OFFSET_CDATA+2], (byte) buf[ISO7816.OFFSET_CDATA +1] };
				
				//sum of arrays without overflow
				overflow = (byte) 0x00;
				for (i=0;i<balance2.length;i++){
				    balance2[i]=(byte) (balance2[i]+tempValue[i]+overflow);
		     /** end credit transaction **/
		     
		/* 2. Calcuate new signature on value file*/
		    tempsign = calculateMac(balance2, (short)0, (short) balance2.length);
//		try{
//			// calculate sign
//			sign = calculateMac(balance2, (short)0, (short) balance2.length);
//			}catch(NullPointerException e) {
//		        ISOException.throwIt((short)0x7800);}
//		     catch(ArrayIndexOutOfBoundsException e) {
//		        ISOException.throwIt((short)0x6801);}
//		     catch(CryptoException e) {
//		        ISOException.throwIt((short)(0x6810+e.getReason()));}
//		
//		/* 3. Build return array in buffer */
		short len1 = Util.arrayCopy(balance2, (byte)0, tmp, (short) 0, (short) (balance2.length));
		short len2 = Util.arrayCopy(tempsign, (byte)0, tmp, (short)len1, (short) (tempsign.length));
		Util.arrayCopy(tmp,(short) 0, buf, (short)0, (short)len2);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) balance2.length);
		apdu.sendBytesLong(buf, (short)0, (short)balance2.length);
				}	
	}
	
	public void debit2(APDU apdu, short dataOffset, short dataLength)throws CryptoException  {
		byte[] buf = apdu.getBuffer();

		tempData = new byte[5];
		// copy buffer in temporary variables	
		tempData = subByteArray(buf, (short)0 , (short)4);
		tempsign = subByteArray(buf, (short)5 , (short)12);
		
		
		/* 1. Verify signature of data*/
		try{
			mac.init(keyDes, Signature.MODE_VERIFY);
			boolean outcome = mac.verify(buf, (short)(0), (short) tempData.length, buf, (short) 6,(short)8);
			//		if (outcome!=true)
			{
			//	ISOException.throwIt((short)0x54);
			}
			}catch(NullPointerException e) {
		        ISOException.throwIt((short)0x1800);}
		     catch(ArrayIndexOutOfBoundsException e) {
		        ISOException.throwIt((short)0x2801);}
		     catch(CryptoException e) {
		        ISOException.throwIt((short)(0x0000+e.getReason()));}

		     /** perform debit transaction **/
//		   store data in buffer in tempData 
				// N.B the terminal sends a 4 byte array lsb first 
				// they are then added in reverse order in tempData
				tempValue = new byte[]{(byte) buf[ISO7816.OFFSET_CDATA+3],(byte) buf[ISO7816.OFFSET_CDATA+2], (byte) buf[ISO7816.OFFSET_CDATA+1], (byte) buf[ISO7816.OFFSET_CDATA] };
				
				//compare tempData with minimum balance
				
				//subtraction of arrays
				for (i=0;i<balance2.length;i++){
				    balance2[i]=(byte) (balance2[i]-tempData[i]);
				}
			/** edn debit transaction **/
			
		/* 2. Calcuate new signature on value file*/
		    tempsign = calculateMac(balance2, (short)0, (short) balance2.length);
//		try{
//			// calculate sign
//			sign = calculateMac(balance2, (short)0, (short) balance2.length);
//			}catch(NullPointerException e) {
//		        ISOException.throwIt((short)0x7800);}
//		     catch(ArrayIndexOutOfBoundsException e) {
//		        ISOException.throwIt((short)0x6801);}
//		     catch(CryptoException e) {
//		        ISOException.throwIt((short)(0x6810+e.getReason()));}
//		
//		/* 3. Build return array in buffer */
		short len1 = Util.arrayCopy(balance2, (byte)0, tmp, (short) 0, (short) (balance2.length));
		short len2 = Util.arrayCopy(tempsign, (byte)0, tmp, (short)len1, (short) (tempsign.length));
		Util.arrayCopy(tmp,(short) 0, buf, (short)0, (short)len2);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) balance2.length);
		apdu.sendBytesLong(buf, (short)0, (short)balance2.length);
		
	}
		
	/**
	 * Calculate MAC
	 * @param byte[]
	 * @return
	 * @throws CryptoException
	 */
	private byte[] calculateMac(byte[] input, short inOff, short inLen) throws CryptoException
	{
		byte[] macArray= new byte[8];
		mac.init(keyDes, Signature.MODE_SIGN);
		try{
			mac.sign(input, inOff, inLen, macArray, (short) 0);
			}catch(NullPointerException e) {
				ISOException.throwIt((short)0x6800);}
			catch(ArrayIndexOutOfBoundsException e) {
				ISOException.throwIt((short)0x6801);}
			catch(CryptoException e) {
				ISOException.throwIt((short)(0x6810+e.getReason()));}
		return macArray;
	}
	/**
	 * 
	 * @param data	
	 * @param dataOff    
	 * @param dataLen
	 * @param signature
	 * @param signOff
	 * @param signLen
	 * @throws CryptoException
	 */
	private void verifyMac(byte[] data, short dataOff, short dataLen, byte[] signature, short signOff, short signLen )  throws CryptoException 
	{
		mac.init(keyDes, Signature.MODE_VERIFY);
		try{
			boolean outcome = mac.verify(data, (short)dataOff, (short) dataLen, signature, (short) signOff,(short)signLen);
					if (outcome!=true)
			{
				ISOException.throwIt((byte)0x10);
			}
		}catch(NullPointerException e) {
	        ISOException.throwIt((short)0x6800);}
	     catch(ArrayIndexOutOfBoundsException e) {
	        ISOException.throwIt((short)0x6801);}
	     catch(CryptoException e) {
	        ISOException.throwIt((short)(0x1100+e.getReason()));}
	}
	
	/**
	 * Smila to verifyMAC but the data is sent via APDU references
	 * 
	 * @param apdu 		
	 * @param dataOff    
	 * @param dataLen
	 * @param signOff
	 * @param signLen
	 * @throws CryptoException
	 */
	private void verifyMacAPDU(APDU apdu, short dataOff, short dataLen, short signOff, short signLen )  throws CryptoException 
	{
		byte[] buf = apdu.getBuffer();
		mac.init(keyDes, Signature.MODE_VERIFY);
		try{
			
			//short len = mac.sign(buf, ISO7816.OFFSET_CDATA, (short)4, signbuf, (short) 0);
			boolean outcome = mac.verify(buf, (short)(ISO7816.OFFSET_CDATA), (short) 4, buf, (short) 9,(short)8);
					if (outcome!=true)
			{
				ISOException.throwIt((short)10);
			}
		}catch(NullPointerException e) {
	        ISOException.throwIt((short)0x6800);}
	     catch(ArrayIndexOutOfBoundsException e) {
	        ISOException.throwIt((short)0x6801);}
	     catch(CryptoException e) {
	        ISOException.throwIt((short)(0x1100+e.getReason()));}
	}
	
	/**
	 * Takes a part of the byte array
	 * 
	 * @param 	input
	 * @param 	inputInit
	 * 			Index of the first byte copied to the subarray
	 * @param 	inputEnd
	 * 			Index of the last byte copied to the subarray
	 * @return
	 */
	public static byte[] subByteArray(byte[]input,short inputInit,short inputEnd)
	{
		byte[] result=new byte[(byte)(inputEnd-inputInit+1)];
		for (short i = inputInit; i <= inputEnd; i++) {
			result[(short)(i-inputInit)]=input[i];
		}
		return result;
	}
	
	/**
	 *  Clear array
	 *  with zeros
	 */
	public static byte[] clearArray (byte[] input)
	{
		byte[] result=new byte[(short)(input.length)];
		for (short i=0; i<=input.length; i++){
			result[(byte)0x00]=input[i];
		}
		return result;
	}
}

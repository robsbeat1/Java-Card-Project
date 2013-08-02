/**
 * 
 */
package des_client_2;



import des_server2.ds2Interface;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * @author Robert
 *
 */
public class Des_client_2 extends Applet {
	
//	 instance variables declaration
	private byte[] tmp = new byte [18];
	private byte[] tempValue = new byte[4];
	private byte[] tempsign = new byte[8];
	private byte[] tempData;
	private byte [] Key8 = {(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x04,
			(byte)0x05,(byte)0x06,(byte)0x07,(byte)0x08};
	
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
	final static  byte SECRET = 0x01;
	
//	 codes of CLA byte in the command APDUs
	final static byte DES_CLA = (byte)0x90;
//	 codes of INS byte in the command APDUs
	public final static byte GET_VALUE=(byte)0x6C;//
	public final static byte CREDIT=(byte)0x0C;//
	public final static byte DEBIT=(byte)0xDC;//
	//Change this if the server AID changes 0a0b0c0d0f01
	byte SERVER_AID [] = {(byte)0xB1, 0x10, 0x20, (byte)0x30, (byte)0x40, 0x11};
	private byte [] server= SERVER_AID;
	
//	Shareble status Words
	public static final short WRONG_SERVER_AID = 0;
	public static final short FAILED_TO_OBTAIN_SIO = 0;
	
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new Des_client_2(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	private Des_client_2(byte[] bArray, short bOffset, byte bLength){
		keyDes = (DESKey) KeyBuilder.buildKey(keyType, keyLength, false);
		keyDes.setKey(Key8, (short) 0);
		mac = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, true);
		
		register();
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		
//		 verify the CLA byte
		if (buf[ISO7816.OFFSET_CLA] != DES_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		switch (buf[ISO7816.OFFSET_INS]) {
		case GET_VALUE:
			getValue(apdu, buf);
			return;
		case CREDIT:
			credit(apdu,buf);
			return;
		case DEBIT:
			debit(apdu,buf);
			return;
		case 0x0B:
			getValue2(apdu,buf);
			return;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			return;
		}
	}
	/**
	 * 	Reads the currently stored value form Value Files
	 * 
	 * 	@note	|| FileN ||	 
	 * 				 1
	 */
	public void getValue(APDU apdu, byte[] buffer){
		// obtain the server AID Object
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
		if (server_aid == null)
			ISOException.throwIt(WRONG_SERVER_AID);
		
		// request the sio from the server
		ds2Interface sio = (ds2Interface)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
		if (sio == null)
			ISOException.throwIt(FAILED_TO_OBTAIN_SIO);
		
		//ask the server to get balance
		sio.getValue(apdu,buffer);
		
	}
	/**
	 * 	Increases a value stored in a Value File
	 * 
	 * 	@note	||	FileN | Data  || 	
	 *                1       4
	 */ 
	
	public void credit(APDU apdu, byte[] buffer){
		// obtain the server AID Object
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
		if (server_aid == null)
			ISOException.throwIt(WRONG_SERVER_AID);
		
		// request the sio from the server
		ds2Interface sio = (ds2Interface)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
		if (sio == null)
			ISOException.throwIt(FAILED_TO_OBTAIN_SIO);
		sio.credit(apdu, buffer);
	}
	
	/**
	 * Decreases a value stored in a Value File
	 * 
	 * @note	||	FileN | Data  || 	
	 */
	public void debit(APDU apdu, byte[] buffer){
		byte[] buf = apdu.getBuffer();
		short dataOff = 0;
		/* 1.Get the data ready */
		tempData = new byte[0x01];
		tempsign = calculateMac(tempData, (short)0, (short) tempData.length);
		
		// obtain the server AID Object
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
		if (server_aid == null)
			ISOException.throwIt(WRONG_SERVER_AID);
		
		// request the sio from the server
		ds2Interface sio = (ds2Interface)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
		if (sio == null)
			ISOException.throwIt(FAILED_TO_OBTAIN_SIO);	
		sio.debit(apdu, buffer);
	}
	
	public void getValue2(APDU apdu, byte[] buffer){
		byte[] buf = apdu.getBuffer();
		short dataOff = 0;
		/* 1.Get the data ready */
		tempData = new byte[ISO7816.OFFSET_LC];
		tempData[0] = (byte)buf[ISO7816.OFFSET_CDATA];
		tempsign = calculateMac(tempData, (short)0, (short) tempData.length);
		
		/* 2.Copy data in buffer array */
		short len = Util.arrayCopy(tempData, (short) 0, buf, (short)0, (short)1);
		short len2 = Util.arrayCopy(tempsign, (byte)0, buf, (short)len, (short) (tempsign.length));
		
		/* 3. SIO invocation*/
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
		if (server_aid == null)
			ISOException.throwIt(WRONG_SERVER_AID);
		
		// request the sio from the server
		ds2Interface sio = (ds2Interface)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
		if (sio == null)
			ISOException.throwIt(FAILED_TO_OBTAIN_SIO);
		
		/* 4. Call method and pass buffer and parameters */
		sio.getValue2(apdu,dataOff,len2);

		/* 5. Verify signature*/
		
		// clear temporary arrays
		//tempsign = clearArray(tempsign);

		// copy buffer in temporary variables	
		tempValue = subByteArray(buf, (short)0 , (short)3);
		tempsign = subByteArray(buf, (short)4 , (short)11);
		
		//mac.init(keyDes, Signature.MODE_VERIFY);
		verifyMac(tempValue, (short)0, (short)4, tempsign, (short)0, (short)8);

		/* 6. If you have reached here, you can send the data*/
		apdu.setOutgoing();
//		// informes the host that the applet will actualy send 
//		// || 4 byte DATA | (otional)8 byte SIGN ||
		apdu.setOutgoingLength((short) tempValue.length);
		
//		// send the valu data 
		apdu.sendBytesLong(tempValue, (short)0, (short) tempValue.length);
		
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
	 * @param apdu 		
	 * @param dataOff    
	 * @param dataLen
	 * @param signOff
	 * @param signLen
	 * @throws CryptoException
	 */
	private void verifyMac(byte[] data, short dataOff, short dataLen, byte[] signature, short signOff, short signLen )  throws CryptoException 
	{
		mac.init(keyDes, Signature.MODE_VERIFY);
		try{
			boolean outcome = mac.verify(data, (short)0, (short) 4, signature, (short) 0,(short)8);
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
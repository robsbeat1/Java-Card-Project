/**
 * 
 */
package des_account;

import des_server2.ds2Interface;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;

/**
 * @author Robert
 *
 */
public class Des_accountClient extends Applet implements ds2Interface {
	
	final static  byte SECRET = 0x01;
	
//	 codes of CLA byte in the command APDUs
	final static byte DES_CLA = (byte)0x90;
//	 codes of INS byte in the command APDUs
	public final static byte GET_VALUE=(byte)0x6C;//
	public final static byte CREDIT=(byte)0x0C;//
	public final static byte DEBIT=(byte)0xDC;//
	//Change this if the server AID changes B010203040
	byte SERVER_AID [] = {(byte)0xB1, 0x10, 0x20, (byte)0x30, (byte)0x40, 0x11};
	private byte [] server= SERVER_AID;
	
//	Shareble status Words
	public static final short WRONG_SERVER_AID = 0;
	public static final short FAILED_TO_OBTAIN_SIO = 0;
	
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new Des_accountClient(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	private Des_accountClient (byte[] bArray, short bOffset, byte bLength){
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
//		 obtain the server AID Object
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
		if (server_aid == null)
			ISOException.throwIt(WRONG_SERVER_AID);
		
		// request the sio from the server
		ds2Interface sio =(ds2Interface)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
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
		
	}
	
	/**
	 * Decreases a value stored in a Value File
	 * 
	 * @note	||	FileN | Data  || 	
	 */
	public void debit(APDU apdu, byte[] buffer){
		
	}
}
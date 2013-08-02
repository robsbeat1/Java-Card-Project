/**
 * This applet holds the value file
 * When a desfire applet needs to read/update the value file it
 * uses the shareble interface objects esposed by this server applet
 * 
 */
package des_server;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.Shareable;
import javacard.framework.Util;


/**
 * @author Robert
 *
 */
public class Des_server extends Applet implements Des_serverInterface{
	
	/****** Constat Declaration ****/
	private static final short SW_UNAUTHORIZED_CLIENT = 0;
	//secret used in SIO
	final static  byte SECRET = 0x01;

	
	//The Client Applet that can access the data in Desfire
	byte CLIENT_AID_BYTES[] = {(byte)0xC0, 0x10, 0x20, (byte)0x30, (byte)0x40, 0x11};
	//byte CLIENT2_AID_BYTES[] = {(byte)0xD0, 0x10, 0x20, (byte)0x30, (byte)0x40, 0x11};
	byte CLIENT2_AID_BYTES[] = {(byte)0xF0, (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 0x11};
	
	private byte[] client = CLIENT_AID_BYTES;
	private byte[] client2 = CLIENT2_AID_BYTES;
	
	
//	creation of SIO
	public Shareable getShareableIntefaceObject (AID client_aid, byte parameter){
		if (parameter != SECRET)
		{
		return null;
		}
		// return SIO
		return this;
	}

	// instance variables declaration
	short value = 658; // Starting balance of decimal 1000 is 3E8 in hex
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new Des_server(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	
	private Des_server(byte[] bArray, short bOffset, byte bLength){
		register();
	} // end of the constructor
	
	
	
	public void process(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		// verify the CLA byte
		if (buffer[ISO7816.OFFSET_CLA] != des_server.Util.SERVER_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
//		 check the INS byte to decide which service method to call
		switch (buffer[ISO7816.OFFSET_INS]) {
		case des_server.Util.CREATE_VALUE_FILE:
			createValueFile(apdu, buffer);
			return;
		case des_server.Util.GET_VALUE:
			getValue(apdu, buffer);
			return;
		case des_server.Util.CREDIT:
			credit(apdu,buffer);
			return;
		case des_server.Util.DEBIT:
			debit(apdu,buffer);
			return;
		case des_server.Util.DELETE_FILE:
			deleteFile(apdu, buffer);
			return;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			return;
		}
	}
	/**
	 *  Creat Value File for 32bit signed integer value
	 *  within the PICC (not in an application)
	 *  
	 *   note	|| FileN | CommunicationSetting | AccessRights | LowerLimit(4) | UpperLimit(4) | Value(4) | LimitedCreditEnabled ||
	 *               1                1                 2             4               4             4                  1 			
	 */
	public void createValueFile(APDU apdu, byte[] buffer){
		
	}
	
	/**
	 * 	Reads the currently stored value form Value Files
	 * 
	 * 	@note	|| FileN ||	 
	 * 				 1
	 */
	public void getValue(APDU apdu, byte[] buffer){
		
//		//get the caller's AID
//		AID client_aid = JCSystem.getPreviousContextAID();
//		
//		// check if this method is indeed by des_client_1
//		if (client_aid.equals(client,(short)0,(byte)(client.length))==false)
//			ISOException.throwIt(SW_UNAUTHORIZED_CLIENT);
				
//		 inform the JCRE that the applet has data to return
		short le = apdu.setOutgoing();
 
		// set the actual number of the outgoing data bytes
		apdu.setOutgoingLength((byte)2);
 
 
		// write the balance into the APDU buffer at the offset 0
		javacard.framework.Util.setShort(buffer, (short)0, (value));
 
		// send the 2-byte balance at the offset
		// 0 in the apdu buffer
		apdu.sendBytes((short)0, (short)2);
		
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
	
	/**
	 * 	Permanently desactivates a file within the file directory of the
	 * 	currently selected application
	 * 
	 * 	@note	|| FileNumber || 	
	 *                  1
	 */
	public void deleteFile(APDU apdu, byte[] buffer){
		
	}
}
	
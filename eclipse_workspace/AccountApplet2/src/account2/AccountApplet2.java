/**
 * Test SERVER 2
 * 
 * Succesfull object sharing example, works with
 * the CLIENT JwalletApplet
 * 
 * No pin required for all oprations
 */
package account2;

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
public class AccountApplet2 extends Applet implements AccountInterface2 {
	
final static  byte SECRET = 0x01;
	
	// the Client applet that access the SIO
	// A0 00 00 00 00 12 34
	
	//byte CLIENT_AID_BYTE []= {(byte) 0xA0,0x00,0x00,(byte)0xAB, (byte)0xCD, 0x02}; 
	byte CLIENT_AID_BYTE []= {(byte) 0xF0,0x10,0x20,(byte)0x30, (byte)0x40, 0x11}; 
	private byte[] client = CLIENT_AID_BYTE;
	
	//creation of SIO
	public Shareable getShareableInterfaceObject (AID client_aid, byte parameter){
		if (parameter != SECRET)
			{
			return null;
			}
		return this;
	}

	/****** Constat Declaration ****/
	 
	// codes of CLA byte in the command APDUs
	final static byte ACCOUNT_CLA = (byte)0xA0;
 
	// codes of INS byte in the command APDUs
	final static byte CREDIT_INS = (byte) 0x30;
	final static byte DEBIT_INS = (byte) 0x40;
	final static byte GET_BALANCE_INS = (byte) 0x50;
 
	// maximum Account balance
	final static short MAX_BALANCE = 10000;
	// maximum transaction amount
	final static short MAX_TRANSACTION_AMOUNT = 5000;
 
	// maximum number of incorrect tries before the
	// PIN is blocked
	//Changed to 4, as a safe guard all. All tests, messages and checks will use 3
	final static byte PIN_TRY_LIMIT =(byte)0x04;
	// maximum size PIN
	final static byte MAX_PIN_SIZE =(byte)0x08;
 
	// Applet-specific status words:
	final static short SW_NO_ERROR = (short) 0x9000;
	final static short SW_VERIFICATION_FAILED = 0x6300;
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6E83;
	final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6E84;
	final static short SW_NEGATIVE_BALANCE = 0x6E85;
	final static short SW_PIN_TO_LONG = 0x6E86;
	final static short SW_PIN_TO_SHORT = 0x6E87;
 
	// instance variables declaration
	short balance = 1000; // Starting balance of decimal 1000 is 3E8 in hex
	
	/**
	 * install method
	 */
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new AccountApplet2(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	
	private AccountApplet2(byte[] bArray, short bOffset, byte bLength){
		register();
	} // end of the constructor
 
	
	public void process(APDU apdu) {
//		 APDU object carries a byte array (buffer) to
		// transfer incoming and outgoing APDU header
		// and data bytes between the card and the host
 
		// at this point, only the first five bytes
		// [CLA, INS, P1, P2, P3] are available in
		// the APDU buffer
		byte[] buffer = apdu.getBuffer();
 
		// return if the APDU is the applet SELECT command
		if (selectingApplet())
			return;
 
		// verify the CLA byte
		if (buffer[ISO7816.OFFSET_CLA] != ACCOUNT_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
 
		// check the INS byte to decide which service method to call
		switch (buffer[ISO7816.OFFSET_INS]) {
		case GET_BALANCE_INS:		getBalance(apdu,buffer); 			return;
		case DEBIT_INS:				debit(apdu,buffer); 	  			return;
		case CREDIT_INS:			credit(apdu,buffer); 				return;
		 //good practice: If you don't know the INStruction, say so:
		default:ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	} // end of process method

	/* in the CREDIT method,the data field of the apdu sent from the CAD, contains 
	 * the ammount of money to be added to the balance 
	 */
	public void credit(APDU apdu, byte[] buffer) {

		//byte[] buffer = apdu.getBuffer();
		// get the number of bytes in the	
		// data field of the command APDU
		byte numBytes = buffer[ISO7816.OFFSET_LC];
 
		//receive data
		//data is read into apdu buffer
		//at offset ISO7816.OFFSET_CDATA
		byte byteRead = (byte)(apdu.setIncomingAndReceive());
 
		short shortAmount = 0;
		if (numBytes == 2){
			shortAmount = (short) Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		}
		else if (numBytes == 1) {
			shortAmount = (short) buffer[ISO7816.OFFSET_CDATA];
		}
 
		// check the credit amount
		if (( shortAmount > MAX_TRANSACTION_AMOUNT)	|| ( shortAmount < 0 )) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		// check the new balance
		if ((short)( balance + shortAmount)  > MAX_BALANCE) {
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
		}
		// credit the amount
		balance = (short)(balance + shortAmount);
		return;
	}
	
	/* in the DEBIT method,the data field of the apdu sent from the CAD, contains 
	 * the ammount of money to be subtracted from the balance 
	 */
	
	
	public void debit(APDU apdu, byte[] buffer) {
	//	byte[] buffer = apdu.getBuffer();
		// get the number of bytes in the
		// data field of the command APDU
		byte numBytes = buffer[ISO7816.OFFSET_LC];
 
		//receive data
		//data is read into apdu buffer
		//at offset ISO7816.OFFSET_CDATA
		byte byteRead = (byte)(apdu.setIncomingAndReceive());
 
		short shortAmount = 0;
		if (numBytes == 2){
			shortAmount = (short) Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		}
		else if (numBytes == 1) {
			shortAmount = (short) buffer[ISO7816.OFFSET_CDATA];
		}
 
		// check the debit amount
		if (( shortAmount > MAX_TRANSACTION_AMOUNT)	|| ( shortAmount < 0 )) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		// check the new balance
		if ((short)( balance - shortAmount)  < 0) {
			ISOException.throwIt(SW_NEGATIVE_BALANCE);
		}
		// debit the amount
		balance = (short)(balance - shortAmount);
		
	}
	/* No verification needed
	 * the method returns the Accounts balance
	 * eg A0500000
	 */
	public void getBalance(APDU apdu, byte[] buffer) {

		// inform the JCRE that the applet has data to return
		short le = apdu.setOutgoing();
 
		// set the actual number of the outgoing data bytes
		apdu.setOutgoingLength((byte)2);
 
 
		// write the balance into the APDU buffer at the offset 0
		Util.setShort(buffer, (short)0, (balance));
 
		// send the 2-byte balance at the offset
		// 0 in the apdu buffer
		apdu.sendBytes((short)0, (short)2);
		
	}
 
} // end of class Account

/**
 * Test SERVER 1
 * 
 * Succesfull object sharing example, works with
 * the CLIENT JwalletApplet
 * 
 */
package account; //Server

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Shareable;
import javacard.framework.TransactionException;
import javacard.framework.Util;

public class AccountApplet extends Applet implements AccountInterface{
	
	// secret used in SIO
	final static  byte SECRET = 0x01;
	
	// the Client applet that access the SIO
	// A0 00 00 00 00 12 34
	
	byte CLIENT_AID_BYTE []= {(byte) 0xA0,0x00,0x00,(byte)0xAB, (byte)0xCD, 0x02}; 
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
	final static byte VERIFY_INS = (byte) 0x20;
	final static byte CREDIT_INS = (byte) 0x30;
	final static byte DEBIT_INS = (byte) 0x40;
	final static byte GET_BALANCE_INS = (byte) 0x50;
	final static byte UPDATE_PIN_INS = (byte) 0x60;
	final static byte ADMIN_RESET_INS = (byte) 0x70;
	final static byte PIN_TRIES_REMAINING_INS = (byte) 0x80;
 
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
	OwnerPIN pin;
	short balance = 1000; // Starting balance of decimal 1000 is 3E8 in hex
	
	/**
	 * install method
	 */
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new AccountApplet(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	private AccountApplet(byte[] bArray, short bOffset, byte bLength){
		 
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		// bArray contains the default PIN initialization value (12345)
		bArray[0] = 01;
		bArray[1] = 02;
		bArray[2] = 03;
		bArray[3] = 04;
		bArray[4] = 05;
		bOffset = 0;
		bLength = 5;
 
		pin.update(bArray, bOffset, bLength);
		// register the applet instance with the JCRE
 
		register();
	} // end of the constructor
 
	
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
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
		case VERIFY_INS:			verify(apdu);				return;
		case UPDATE_PIN_INS:		updatePin(apdu);			return;
		case ADMIN_RESET_INS:		adminRest();				return;
		case PIN_TRIES_REMAINING_INS:getPinTriesRemaining(apdu); return;
		 //good practice: If you don't know the INStruction, say so:
		default:ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	} // end of process method

	/* in the DEBIT method,the data field of the apdu sent from the CAD, contains 
	 * the ammount of money to be subtracted from the balance 
	 */
	
//	private void debit(APDU apdu) {
// 
//		// verify authentication
//		if (!pin.isValidated()){
//			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//		}
//		byte[] buffer = apdu.getBuffer();
//		// get the number of bytes in the
//		// data field of the command APDU
//		byte numBytes = buffer[ISO7816.OFFSET_LC];
// 
//		//receive data
//		//data is read into apdu buffer
//		//at offset ISO7816.OFFSET_CDATA
//		byte byteRead = (byte)(apdu.setIncomingAndReceive());
// 
//		short shortAmount = 0;
//		if (numBytes == 2){
//			shortAmount = (short) Util.getShort(buffer, ISO7816.OFFSET_CDATA);
//		}
//		else if (numBytes == 1) {
//			shortAmount = (short) buffer[ISO7816.OFFSET_CDATA];
//		}
// 
//		// check the debit amount
//		if (( shortAmount > MAX_TRANSACTION_AMOUNT)	|| ( shortAmount < 0 )) {
//			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
//		}
//		// check the new balance
//		if ((short)( balance - shortAmount)  < 0) {
//			ISOException.throwIt(SW_NEGATIVE_BALANCE);
//		}
//		// debit the amount
//		balance = (short)(balance - shortAmount);
//	}		// end of debit method
//	
	/* in the CREDIT method,the data field of the apdu sent from the CAD, contains 
	 * the ammount of money to be added to the balance 
	 */
//	private void credit(APDU apdu) {
// 
//		// verify authentication
//		if (!pin.isValidated()){
//			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//		}
//		byte[] buffer = apdu.getBuffer();
//		// get the number of bytes in the	
//		// data field of the command APDU
//		byte numBytes = buffer[ISO7816.OFFSET_LC];
// 
//		//receive data
//		//data is read into apdu buffer
//		//at offset ISO7816.OFFSET_CDATA
//		byte byteRead = (byte)(apdu.setIncomingAndReceive());
// 
//		short shortAmount = 0;
//		if (numBytes == 2){
//			shortAmount = (short) Util.getShort(buffer, ISO7816.OFFSET_CDATA);
//		}
//		else if (numBytes == 1) {
//			shortAmount = (short) buffer[ISO7816.OFFSET_CDATA];
//		}
// 
//		// check the credit amount
//		if (( shortAmount > MAX_TRANSACTION_AMOUNT)	|| ( shortAmount < 0 )) {
//			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
//		}
//		// check the new balance
//		if ((short)( balance + shortAmount)  > MAX_BALANCE) {
//			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
//		}
//		// credit the amount
//		balance = (short)(balance + shortAmount);
//		return;
//		}
 
	/**
	 * Verify then
	 * Update/change pin
	 * byte[] bArray is the pin
	 * short bOffset is the position in the array the pin starts in the bArray
	 * byte bLength is the lenght of the pin
	 */
	private void updatePin(APDU apdu) {
		//	byte[] bArray, short bOffset, byte bLength){
		// 		First check the original pin
		//		verify authentication
		if (! pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
 
		byte[] buffer = apdu.getBuffer();
 
		// get the number of bytes in the
		// data field of the command APDU -- OFFSET_LC = positon 4
		byte numBytes = buffer[ISO7816.OFFSET_LC];
 
 
		// recieve data
		// data are read into the apdu buffer
		// at the offset ISO7816.OFFSET_CDATA
		byte byteRead = (byte)(apdu.setIncomingAndReceive());
 
		// error if the number of data bytes
		// read does not match the number in the Lc byte
		if (byteRead != numBytes) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
 
		if ( numBytes > 8 )
			ISOException.throwIt(SW_PIN_TO_LONG);
 
		if ( numBytes < 4 )
			ISOException.throwIt(SW_PIN_TO_SHORT);
 
 
		short offset_cdata = 05;		
		pin.update(buffer, offset_cdata, numBytes);
		pin.resetAndUnblock();
 
 
	}
 
	/**
	 *  Admin method
	 *  Rest the pin attempts and unblock
	 *  @param apdu
	 */
	private void adminRest() {
		try {
			pin.resetAndUnblock();
		} catch (RuntimeException e) {
			// TODO Auto-generated catch block
		}
		return;
	}
 
	/**
	 * Get number of remaining pin tries
	 * @param apdu
	 */
	private void getPinTriesRemaining(APDU apdu) {
		try {
			byte[] buffer = apdu.getBuffer();
			// inform the JCRE that the applet has data to return
			short le = apdu.setOutgoing();
			// set the actual number of the outgoing data bytes
			apdu.setOutgoingLength((byte)2);
 
			// write the PinTriesRemaining into the APDU buffer at the offset 0
			Util.setShort(buffer, (short)0, pin.getTriesRemaining());
 
			// send the 2-byte balance at the offset
			// 0 in the apdu buffer
			apdu.sendBytes((short)0, (short)2);
		} catch (APDUException e) {
			// TODO Auto-generated catch block
		} catch (TransactionException e) {
			// TODO Auto-generated catch block
		} catch (ArrayIndexOutOfBoundsException e) {
			// TODO Auto-generated catch block
		} catch (NullPointerException e) {
			// TODO Auto-generated catch block
		}
 
	} // end of getPinTriesRemaining method
 
	/**
	 * No verification needed
	 * the method returns the Accounts balance
	 * eg A0500000
	 */
//	private void getBalance(APDU apdu) {
// 
//		byte[] buffer = apdu.getBuffer();
// 
//		// inform the JCRE that the applet has data to return
//		short le = apdu.setOutgoing();
// 
//		// set the actual number of the outgoing data bytes
//		apdu.setOutgoingLength((byte)2);
// 
// 
//		// write the balance into the APDU buffer at the offset 0
//		Util.setShort(buffer, (short)0, (balance));
// 
//		// send the 2-byte balance at the offset
//		// 0 in the apdu buffer
//		apdu.sendBytes((short)0, (short)2);
// 
//	}
	
	/**
	 * Verification method to verify the PIN
	 * @param apdu
	 */
	private void verify(APDU apdu) {
 
		byte[] buffer = apdu.getBuffer();
 
		// receive the PIN data for validation.
		byte byteRead = (byte)(apdu.setIncomingAndReceive());
 
		// check pin
		// the PIN data is read into the APDU buffer
		// starting at the offset ISO7816.OFFSET_CDATA
		// the PIN data length = byteRead
		if (pin.check(buffer, ISO7816.OFFSET_CDATA,byteRead)
				== false)
			ISOException.throwIt(SW_VERIFICATION_FAILED);
 
	} // end of verify method

	
	public void credit(APDU apdu, byte[] buffer) {
//		 verify authentication
		if (!pin.isValidated()){
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
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
	
	
	public void debit(APDU apdu, byte[] buffer) {
//		 verify authentication
		if (!pin.isValidated()){
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
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

	public void getBalance(APDU apdu, byte[] buffer) {

//		 inform the JCRE that the applet has data to return
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

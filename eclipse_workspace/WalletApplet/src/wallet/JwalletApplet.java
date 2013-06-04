/**
 * Test CLIENT 1
 * 
 * Succesfull object sharing example, works with
 * the SERVER AccountApplet2
 * 
 */
package wallet; //Client

import account2.AccountInterface2;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

public class JwalletApplet extends Applet {
	
	
	final static  byte SECRET = 0x01;
	
	//Change this if the server AID changes
	
	byte SERVER_AID [] = {(byte)0xA0, 0x00, 0x00, (byte)0xAB, (byte)0xEF, 0x02};
	private byte [] server= SERVER_AID;

	/****** Constat Declaration ****/
	 
	// codes of CLA byte in the command APDUs
	final static byte ACCOUNT_CLA = (byte)0xB0;
	
	// codes of INS byte in the command APDUs
	final static byte VERIFY = (byte)0x20;
	final static byte CREDIT = (byte) 0x30;
	final static byte DEBIT = (byte) 0x40;
	final static byte GET_BALANCE = (byte) 0x50;
 
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
		new JwalletApplet(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	private JwalletApplet(byte[] bArray, short bOffset, byte bLength){
		 
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		// bArray contains the default PIN initialization value (54321)
		bArray[0] = 05;
		bArray[1] = 04;
		bArray[2] = 03;
		bArray[3] = 02;
		bArray[4] = 01;
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

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case GET_BALANCE : getBalance(apdu,buf);
		return;
		case DEBIT : debit(apdu,buf);
		return;
		case CREDIT: credit(apdu,buf);
		return;
		case VERIFY: verify(apdu,buf);
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void getBalance(APDU apdu, byte[] buffer) {
	
//		obtain the server Object
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
//		request the sio from the server
		AccountInterface2 sio =(AccountInterface2)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
//		 ask the server to get balance
		sio.getBalance(apdu, buffer);
		
	}
	
	private void debit(APDU apdu, byte[] buffer) {
//		obtain the server Object
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
//		request the sio from the server
		AccountInterface2 sio =(AccountInterface2)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
		sio.debit(apdu, buffer);
			
		}
	private void credit(APDU apdu, byte[] buffer) {
//		obtain the server Object
		AID server_aid = JCSystem.lookupAID(server, (short) 0, (byte)server.length);
//		request the sio from the server
		AccountInterface2 sio =(AccountInterface2)(JCSystem.getAppletShareableInterfaceObject(server_aid, SECRET));
		sio.credit(apdu, buffer);
		
	}
	private void verify (APDU apdu, byte[] buffer){
//		 receive the PIN data for validation.
		byte byteRead = (byte)(apdu.setIncomingAndReceive());
 
		// check pin
		// the PIN data is read into the APDU buffer
		// starting at the offset ISO7816.OFFSET_CDATA
		// the PIN data length = byteRead
		if (pin.check(buffer, ISO7816.OFFSET_CDATA,byteRead)
				== false)
			ISOException.throwIt(SW_VERIFICATION_FAILED);
 
	} // end of verify method

		
	}
	


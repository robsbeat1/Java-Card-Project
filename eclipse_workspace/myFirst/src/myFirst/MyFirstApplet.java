/**
 * 
 */
package myFirst;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;

/**
 * @author Robert
 *
 */
public class MyFirstApplet extends Applet {
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// public stati void -> The JCRE calls this static method to create an instance of the Applet subclass.
		// GP-compliant JavaCard applet registration
		new MyFirstApplet().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x00:
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
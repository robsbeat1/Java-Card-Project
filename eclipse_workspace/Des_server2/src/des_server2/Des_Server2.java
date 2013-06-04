/**
 * 
 */
package des_server2;

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
public class Des_Server2 extends Applet implements ds2Interface {
	
	
    //Des_client1
	byte CLIENT1_AID_BYTE[] = {(byte)0xC0, (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, (byte)0x11};
	private byte[] client1 = CLIENT1_AID_BYTE;
	
	//Des_client2
	byte CLIENT2_AID_BYTE []= {(byte) 0xD0, (byte)0x10,(byte)0x20,(byte)0x30, (byte)0x40, (byte)0x11}; 
	private byte[] client2 = CLIENT2_AID_BYTE;
	
	//creation of SIO
	public Shareable getShareableInterfaceObject (AID client_aid, byte parameter){
		if (parameter != des_server2.Util.SECRET)
			{
			return null;
			}
		return this;
	}
	// instance variables declaration
	private byte[] balance2 = new byte[]{ (byte)0xe00, 0x4f, (byte)0xd0, (byte) 0x00};
	private byte[] tempData;
	private short i;
	private short overflow;
	/**
	 * install method
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new Des_Server2(bArray, bOffset, bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}
	
	private Des_Server2(byte[] bArray, short bOffset, byte bLength){
		
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

	public void getValue(APDU apdu, byte[] buffer) {

		// inform the JCRE that the applet has data to return
		//expected lenght of response (Le)
		short le = apdu.setOutgoing();
		
		
		// informes the host that the applet will actualy 
		// send 4 bytes
		apdu.setOutgoingLength((byte)4);
 
 
		// write the balance into the APDU buffer at the offset 0
		//Util.setShort(buffer, (short)0, (balance));
		
		// send the 2-byte balance at the offset
		// 0 in the apdu buffer
		//apdu.sendBytes((short)0, (short)2);
		apdu.sendBytesLong(balance2, (short)0, (short) balance2.length);
	}
	public void limitedCredit (APDU apdu, byte[] buffer){
		//		 TODO
	}
}
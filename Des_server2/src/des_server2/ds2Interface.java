package des_server2;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface ds2Interface extends Shareable{
	
	public void getValue(APDU apdu, byte[] buffer);
	public void debit(APDU apdu, byte[] buffer);
	public void credit(APDU apdu, byte[] buffer);
	// for mac verification
	public void getValue2(APDU apdu, short dataOffset,short dataLength);
	public void credit2(APDU apdu, short dataOffset,short dataLength);
	public void debit2(APDU apdu, short dataOffset,short dataLength);
}

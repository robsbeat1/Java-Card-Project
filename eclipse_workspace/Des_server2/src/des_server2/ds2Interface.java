package des_server2;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface ds2Interface extends Shareable{
	
	public void getValue(APDU apdu, byte[] buffer);
	public void debit(APDU apdu, byte[] buffer);
	public void credit(APDU apdu, byte[] buffer);
}

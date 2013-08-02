package des_1;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface ds2Interface extends Shareable{
	
	public void selectApplication(APDU apdu, byte[] buffer);
	public void createValueFile(APDU apdu, byte[] buffer);
	public void getValue(APDU apdu, byte[] buffer);
	public void credit(APDU apdu, byte[] buffer);
	public void debit(APDU apdu, byte[] buffer);
	public void getBalance(APDU apdu, byte[] buffer);
	
}

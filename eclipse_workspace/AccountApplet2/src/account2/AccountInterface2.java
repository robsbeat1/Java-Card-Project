package account2;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface AccountInterface2 extends Shareable{
	
	public void getBalance(APDU apdu, byte[] buffer);
	public void debit(APDU apdu, byte[] buffer);
	public void credit(APDU apdu, byte[] buffer);
}

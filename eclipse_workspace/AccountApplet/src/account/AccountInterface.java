package account;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface AccountInterface extends Shareable{
	
	public void getBalance(APDU apdu, byte[] buffer);
	public void debit(APDU apdu, byte[] buffer);
	public void credit(APDU apdu, byte[] buffer);

}

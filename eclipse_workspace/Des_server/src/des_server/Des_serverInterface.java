package des_server;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface Des_serverInterface extends Shareable{

	public void getValue(APDU apdu, byte[] buffer);
	public void credit(APDU apdu, byte[] buffer);
	public void debit (APDU apdu, byte[] buffer);

}

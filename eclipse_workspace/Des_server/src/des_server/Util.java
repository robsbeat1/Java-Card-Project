package des_server;

public class Util {
//Commands code
//	 codes of CLA byte in the command APDUs
	final static byte SERVER_CLA = (byte)0x90;
//	 codes of INS byte in the command APDUs
	public final static byte CREATE_VALUE_FILE=(byte) 0xCC;//
	public final static byte GET_VALUE=(byte)0x6C;//
	public final static byte CREDIT=(byte)0x0C;//
	public final static byte DEBIT=(byte)0xDC;//
	public final static byte DELETE_FILE=(byte)0xDF;//
	
}

package des_server2;

public class Util {

	//	Commands code
	
	//	 codes of CLA byte in the command APDUs
	public final static byte SERVER_CLA = (byte)0x90;
	//	 codes of INS byte in the command APDUs
	public final static byte CREATE_VALUE_FILE=(byte) 0xCC;//
	public final static byte GET_VALUE=(byte)0x6C;//
	public final static byte CREDIT=(byte)0x0C;//
	public final static byte LIMITED_CREDIT=(byte)0x1C;
	public final static byte DEBIT=(byte)0xDC;//
	public final static byte DELETE_FILE=(byte)0xDF;//
	
	//	Status Word
	public final static short OPERATION_OK=(short)0x9100;
	public final static short NO_CHANGES=(short)0x910C;
	public final static short OUT_OF_EEPROM_ERROR=(short)0x910E;
	public final static short ILLEGAL_COMMAND_CODE=(short)0x911C;
	public final static short INTEGRITY_ERROR=(short)0x911E;
	public final static short NO_SUCH_KEY=(short)0x9140;
	public final static short LENGTH_ERROR=(short)0x917E;
	public final static short PERMISSION_DENIED=(short)0x919D;
	public final static short PARAMETER_ERROR=(short)0x919E;
	public final static short APPLICATION_NOT_FOUND=(short)0x91A0;
	public final static short APPL_INTEGRITY_ERROR=(short)0x91A1;
	public final static short AUTHENTICATION_ERROR=(short)0x91AE;
	public final static short ADDITIONAL_FRAME=(short)0x91AF;
	public final static short BOUNDARY_ERROR=(short)0x91BE;
	public final static short PICC_INTEGRITY_ERROR=(short)0x91C1;
	public final static short COMMAND_ABORTED=(short)0X91CA;
	public final static short PICC_DISABLED_ERROR=(short)0x91CD;
	public final static short COUNT_ERROR=(short)0x91CE;
	public final static short DUPLICATE_ERROR=(short)0x91DE;
	public final static short EEPROM_ERROR=(short)0x91EE;
	public final static short FILE_NOT_FOUND=(short)0x91F0;
	public final static short FILE_INTEGRITY_ERROR=(short)0x91F1;
	// New Errors
	public final static short WRONG_VALUE_ERROR=(short)0x916E;
	
	// Transmission modes
	final static byte PLAIN_COMMUNICATION=(byte)0x00;
	final static byte PLAIN_COMMUNICATION_MAC=(byte)0x01;
	final static byte FULLY_ENCRYPTED=(byte)0x02;
	
	//Lowest balance
	public final static byte[] MIN_BALANCE ={(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
	

}

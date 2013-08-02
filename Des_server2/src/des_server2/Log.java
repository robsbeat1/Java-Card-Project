package des_server2;
/**
 * This class stores the log file
 * 
 * wrtieLog writes a 16 byte array for each log
 * 
 * 
 * @author Robert
 *
 */



public class Log {
	private byte[] log = new byte[70];
	private short insCount;
		
		
	protected void writeLog(byte operation, byte[] value, byte[] aid)
	{
		
	}
	
	protected byte[] readLog()
	{
		return log;
	}
	
	protected void clerLog()
	{
		
	}

}

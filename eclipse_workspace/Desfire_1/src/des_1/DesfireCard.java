package des_1; //SERVER

import org.bouncycastle.jce.interfaces.ConfigurableProvider;
import javacard.framework.*;
import javacard.framework.service.BasicService;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.SecretKey;
import javacardx.crypto.Cipher;

/**
 * 		DESfire Card operating system's emulation. This class installs the applet
 * 	in the card and runs the OS reading APDU's and calling the required functions
 * 	depending on the INS field
 * 
 * 	@author WinXp
 *
 */

public class DesfireCard extends Applet implements ds2Interface{
	
	private static final short SW_UNAUTHORIZED_CLIENT = 0;
	// secret used in SIO
	final static  byte SECRET = 0x01;
	//	The Client Applet that can access the data in Desfire
	byte CLIENT_AID_BYTES[] = {(byte)0xD0,0x10, 0x20,0x30,0x40, 0x11};
	private byte[] client = CLIENT_AID_BYTES;
	
//	creation of SIO
	public Shareable getShareableIntefaceObject (AID client_aid, byte parameter){
		if(client_aid.equals(client, (short) 0, (byte)(client.length)) == false)
			return null;
		if (parameter != SECRET)
		{
		return null;
		}
		// return SIO
		return (this);
	}
// custome balance
	short balance = 1000;
	/**
	 * 	Master file of the card
	 */
	protected MasterFile masterFile;
	
	/**
	 * 	File selected
	 */
	private File selectedFile;
	
	/**
	 * 	Directory file selected
	 */
	private DirectoryFile selectedDF;
	
	/**
	 * 	Sets wich command has to continue after a CONTINUE command
	 */
	private byte commandToContinue;//para comandos que necesitan continuar
	
	/**
	 * 	Used in R/W operations to keep the number of bytes processed so far
	 */
//	private short readed;
//	
	/**
	 * 	Pointer to the location where the operaton will continue
	 */
//	private short offset;
//	
	/**
	 * 	Number of bytes not processed yet
	 */
//	private short bytesLeft;
	
	/**
	 * 		Keeps the number of the key that is going to be authenticated during
	 * 	the authenticate operation
	 */
	private byte keyNumberToAuthenticate;
	
	/**
	 * 	Key number that has been authenticated last
	 */
	private byte authenticated;
	
	/**
	 * 	Sets if the messages are sent plain, with MAC or enciphered.
	 */
	byte securityLevel;
	
	/**
	 * 	Security level of the file that is being readed
	 */
	byte fileSecurityLevel;
	
	/**
	 * 	Current session key
	 */
	Key sessionKey;

	
	private RandomData randomData;
	private Cipher cipher;
	private byte[] dataBuffer;
	byte[] randomNumberToAuthenticate;
	BasicService bs;
	

	
   /**
	 * called by the JCRE to create an applet instance
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// create a eID card applet instance
		new DesfireCard();
	}
	
	/**
	 * private constructor - called by the install method to instantiate a
	 * EidCard instance
	 * 
	 * needs to be protected so that it can be invoked by subclasses
	 */
	protected DesfireCard() {
		masterFile=new MasterFile();
		selectedDF=masterFile;
		if (this.randomData == null)
			this.randomData=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);			
		if (this.cipher == null)
			this.cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
//		offset=0;
//		bytesLeft=0;
		keyNumberToAuthenticate=0;
		authenticated=Util.NO_KEY_AUTHENTICATED;
		sessionKey=(DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
		sessionKey.clearKey();
		securityLevel=Util.PLAIN_COMMUNICATION;
		bs=new BasicService();
		
		// register the applet instance with the JCRE
		register();
	}
			
	public void process(APDU apdu) {
		// return if the APDU is the applet SELECT command
		if (selectingApplet())
			return;
		
		byte[] buffer = apdu.getBuffer();
		
		
		if(authenticated==-1)this.securityLevel=Util.PLAIN_COMMUNICATION;
	    if((commandToContinue!=Util.NO_COMMAND_TO_CONTINUE) && (buffer[ISO7816.OFFSET_INS]!=(byte)0xAF)){
	    	clear();	    	
	    	ISOException.throwIt((short) Util.COMMAND_ABORTED);
	    }
		// check the INS byte to decide which service method to call
		switch (buffer[ISO7816.OFFSET_INS]) {
		case Util.AUTHENTICATE:
			authenticate(apdu,buffer);
			break;
		case Util.CHANGE_KEY_SETTINGS:
			changeKeySettings(apdu,buffer);
			break;
		case Util.CHANGE_KEY:
			changeKey(apdu,buffer);
			break;		
		case Util.CREATE_APPLICATION:
			createApplication(apdu, buffer);
			break;
		case Util.DELETE_APPLICATION:
			deleteApplication(apdu, buffer);
			break;
		case Util.GET_APPLICATION_IDS:
			getApplicationIDs(apdu,buffer);
			break;
		case Util.GET_KEY_SETTINGS:
			getKeySettings(apdu, buffer);
			break;
		case Util.SELECT_APPLICATION:
			selectApplication(apdu, buffer);
			break;
		case Util.FORMAT_PICC:
			formatPICC(apdu, buffer);
			break;
		case Util.SET_CONFIGURATION:
			setConfiguration(apdu,buffer);
			break;
		case Util.GET_FILE_IDS:
			getFileIDs(apdu, buffer);
			break;
		case Util.CREATE_VALUE_FILE:
			createValueFile(apdu, buffer);
			break;
		case Util.DELETE_FILE:
			deleteFile(apdu, buffer);
			break;
		case Util.GET_VALUE:
			getValue(apdu, buffer);
			break;
		case Util.CREDIT:
			credit(apdu,buffer);
			break;
		case Util.DEBIT:
			debit(apdu,buffer);
			break;
		case Util.COMMIT_TRANSACTION:
			commitTransaction(apdu, buffer);
			break;
		case Util.ABORT_TRANSACTION:
			abortTransaction(apdu, buffer);
			break;
		case Util.GET_BALANCE:
			getBalance(apdu, buffer);
			break;
		case Util.CONTINUE:
			switch(commandToContinue){
			case Util.AUTHENTICATE:
				authenticate(apdu,buffer);
				break;
			case Util.GET_APPLICATION_IDS:
				getApplicationIDs(apdu, buffer);
				break;

			default:
				ISOException.throwIt((short) 0x911C);
				break;
			}
			break;
		default:
			ISOException.throwIt((short) 0x911C);
			break;
		}
	}
	
	/**
	 * PICC and reader device show in an encrypted way that they posses the same key.
	 *  
	 * @effect	Confirms that both entities are permited to do operations on each 
	 * 			other and creates a session key.
	 * @note	This procedure has two parts. depending on the commandToContinue status.
	 * @note	||KeyNumber|| 
	 * 			
	 */
	private void authenticate(APDU apdu, byte[] buffer){
	//APDU: KeyNo
		receiveAPDU(apdu, buffer);
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			//FIRST MESSAGE
			
			if((byte)(buffer[ISO7816.OFFSET_LC])!=1)ISOException.throwIt(Util.LENGTH_ERROR);
			// RndB is generated			
			keyNumberToAuthenticate=buffer[ISO7816.OFFSET_CDATA];
			if(!selectedDF.isValidKeyNumber(keyNumberToAuthenticate))ISOException.throwIt(Util.NO_SUCH_KEY);
			randomNumberToAuthenticate=new byte[8];
			randomData.generateData(randomNumberToAuthenticate,(short) 0,(short) 8);
			//Ek(RndB) is created
			byte[] ekRndB=new byte[8];
			if(selectedDF.isMasterFile())cipher.init(selectedDF.getMasterKey(), Cipher.MODE_ENCRYPT);
			else cipher.init(selectedDF.getKey(keyNumberToAuthenticate), Cipher.MODE_ENCRYPT);
			cipher.doFinal(randomNumberToAuthenticate, (short)0,(short)8, ekRndB, (short)0);
			commandToContinue=Util.AUTHENTICATE;

			//Ek(RndB) is sent
			sendResponse(apdu, buffer, ekRndB,(byte)0xAF);
		}
		else{
			//SECCOND MESSAGE 
			if((byte)(buffer[ISO7816.OFFSET_LC])!=16)ISOException.throwIt(Util.LENGTH_ERROR);
			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
			byte[] encryptedRndA=new byte[8];
			byte[] encryptedRndArndB=new byte[16];
			byte[] rndA=new byte[8];
			byte[] rndB=new byte[8];
			byte[] rndArndB=new byte[16];
			//Ek(RndA-RndB') is recieved. RndB' is a 8 bits left-shift of RndB	
			encryptedRndArndB=Util.subByteArray(buffer, (byte)ISO7816.OFFSET_CDATA, (byte)(ISO7816.OFFSET_CDATA+16));
			if(selectedDF.isMasterFile())cipher.init(selectedDF.getMasterKey(), Cipher.MODE_DECRYPT);
			else cipher.init(selectedDF.getKey(keyNumberToAuthenticate), Cipher.MODE_DECRYPT);
			cipher.doFinal(encryptedRndArndB, (short)0, (short)16, rndArndB, (short)0);
			rndA=Util.subByteArray(rndArndB, (byte)0, (byte)7);
			rndB=Util.subByteArray(rndArndB, (byte)8, (byte)15);
			rndB=Util.rotateRight(rndB);//Because rndB was left shifted
			//RndB is checked
			if(javacard.framework.Util.arrayCompare(rndB,(short)0,randomNumberToAuthenticate,(short)0,(short)rndB.length)!=0){
				//Authentication Error
				authenticated=Util.NO_KEY_AUTHENTICATED;
				ISOException.throwIt(Util.AUTHENTICATION_ERROR);
			}
			else {
				//The key is authenticated
				authenticated=keyNumberToAuthenticate;
			}
			//Session key is created
			byte[] newSessionKey=Util.create3DESSessionKey(rndA,rndB);
			
			//Ek(RndA')is sent back
			rndA=Util.rotateLeft(rndA);
			if(selectedDF.isMasterFile())cipher.init(selectedDF.getMasterKey(), Cipher.MODE_ENCRYPT);
			else cipher.init(selectedDF.getKey(keyNumberToAuthenticate), Cipher.MODE_ENCRYPT);
			cipher.doFinal(rndA, (short)0,(short)8, encryptedRndA, (short)0);
			sendResponseAndChangeStatus(apdu, buffer,encryptedRndA,newSessionKey);				
		}
	}
	
	/**
	 * Changes the master key settings on PICC and application level
	 * 
	 * 	@note	||Ciphered Key Settings||
	 * 				8/16	
	 */
	private void changeKeySettings(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		//Hay que descifrar el campo de datos igual que con changeKey (no sé como)
		//FALTA
		if(((byte)(buffer[ISO7816.OFFSET_LC])!=8)&&((byte)(buffer[ISO7816.OFFSET_LC])!=16))ISOException.throwIt(Util.LENGTH_ERROR);
		byte keySettings=buffer[ISO7816.OFFSET_CDATA];
		if(!selectedDF.hasKeySettingsChangeAllowed(authenticated))ISOException.throwIt(Util.PERMISSION_DENIED);
		if(selectedDF.getFileID()==(byte)0x00){
			masterFile.changeKeySettings(keySettings);
			selectedDF=masterFile;
		}
		else{
			selectedDF.changeKeySettings(keySettings);
			masterFile.arrayDF[selectedDF.getFileID()]=selectedDF;//Actualizamos
		}
		ISOException.throwIt(Util.OPERATION_OK);		
	}
	
	/**
	 * Changes any key stored on the PICC
	 * 
	 * @note ||Key number | Ciphered Key Data||
	 * 				1			24-40	
	 */	
	private void changeKey(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		
		if(((byte)(buffer[ISO7816.OFFSET_LC])<25)&&((byte)(buffer[ISO7816.OFFSET_LC])>41))ISOException.throwIt(Util.LENGTH_ERROR);
		byte keyN=buffer[ISO7816.OFFSET_CDATA];
		if((selectedDF.isMasterFile()==true)&&(keyN!=0))ISOException.throwIt(Util.PARAMETER_ERROR);
		if((selectedDF.isMasterFile()==false)&&(keyN>=28))ISOException.throwIt(Util.PARAMETER_ERROR);
		if(selectedDF.hasChangeAccess(authenticated,keyN)==false)ISOException.throwIt(Util.PERMISSION_DENIED);

		byte[] encipheredKeyData = new byte[(byte)(buffer[ISO7816.OFFSET_LC]-1)];
		for (byte i = 0; i < encipheredKeyData.length; i++) {
			encipheredKeyData[i]=buffer[(byte)(ISO7816.OFFSET_CDATA+i+1)];		
		}
		
		byte[] newKeyDecrypted=decryptEncipheredKeyData(encipheredKeyData, keyN);
		
		
		if(selectedDF.isMasterFile()){
			if(authenticated==keyN)authenticated=Util.NO_KEY_AUTHENTICATED;
			masterFile.changeKey(keyN,newKeyDecrypted);
			selectedDF=masterFile;
		}
		else{
			if(authenticated==keyN)authenticated=Util.NO_KEY_AUTHENTICATED;
			selectedDF.changeKey(keyN,newKeyDecrypted);
			masterFile.arrayDF[selectedDF.getFileID()]=selectedDF;
		}
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Creates a new oplication on the PICC
	 * 
	 * 	@note	|| AID | KeySettings1 | KeySettings2 | ISOFileID* | DF_FILE* ||
	 * 				3		   1			  1             2		1-16	 
	 */
	private void createApplication(APDU apdu, byte[] buffer){
		
		receiveAPDU(apdu, buffer);
		if(((byte)(buffer[ISO7816.OFFSET_LC])<5)&&((byte)(buffer[ISO7816.OFFSET_LC])>23))ISOException.throwIt(Util.LENGTH_ERROR);
		
		if(masterFile.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		if(masterFile.getIndexDF().hasWriteAccess((byte)0)==false) ISOException.throwIt(Util.PERMISSION_DENIED);//CREO QUE SOBRA
		byte[] AID = {buffer[ISO7816.OFFSET_CDATA],buffer[ISO7816.OFFSET_CDATA+1],buffer[ISO7816.OFFSET_CDATA+2]};
		byte[] keySettings={buffer[ISO7816.OFFSET_CDATA+3],buffer[ISO7816.OFFSET_CDATA+4]};
		
		//Añadir el ISOFileID y el DF-Name  para compatibiliadad con 7816
		//FALTA
		masterFile.addDF(AID,keySettings);
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Permanently desactivates applications on the PICC
	 * 
	 * 	@effect If the application that is going to be removed is the currently selected
	 * 			the PICC level is set
	 * 	@note	|| AID ||
	 * 				3
	 */
	private void deleteApplication(APDU apdu, byte[] buffer){
		
		receiveAPDU(apdu, buffer);
		if(((byte)(buffer[ISO7816.OFFSET_LC])!=3))ISOException.throwIt(Util.LENGTH_ERROR);
		byte[] AID= {buffer[ISO7816.OFFSET_CDATA],buffer[ISO7816.OFFSET_CDATA+1],buffer[ISO7816.OFFSET_CDATA+2]};
		if(masterFile.searchAID(AID)==-1)ISOException.throwIt(Util.APPLICATION_NOT_FOUND);
		if(masterFile.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		
		//If the application that is going to be removed is the currently selected the PICC level is set
		if(selectedDF.getFileID()==masterFile.searchAID(AID))selectedDF=masterFile;
		masterFile.deleteDF(AID);
		if(selectedDF.isMasterFile())selectedDF=masterFile;
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Returns the application identifiers of all applications on a PICC
	 * 	@note	If the number of applications is higher than 19 the command will
	 * 			work in two parts. 
	 */
	private void getApplicationIDs(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=0)ISOException.throwIt(Util.LENGTH_ERROR);
		 byte[] response;
		 byte numApp=(byte)(masterFile.numApp-1);//-1 because the IndexFile won't be included
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			if(masterFile.hasGetRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
			if(numApp==0)ISOException.throwIt(Util.OPERATION_OK);
			if(numApp==1){
				sendResponse(apdu,buffer,masterFile.getAID((byte) 1));
				return;
			}
			if(numApp>19){
				response=new byte[(byte)19*3];
				commandToContinue=Util.GET_APPLICATION_IDS;
			}
			else response=new byte[(byte)(numApp*3)];
			for (byte i = 0; i < response.length; i=(byte)(i+3)) {
				byte[] AID=masterFile.getAID((byte)(i/3+1));//+1 because the IndexFile won't be included
				response[i]=AID[0];
				response[(byte)(i+1)]=AID[1];
				response[(byte)(i+2)]=AID[2];
			}
//			ISOException.throwIt(response[3]);
			//Habría que devolver STATUS WORD AF si hay más AID q enviar
			sendResponse(apdu, buffer, response);
		}
		else{//Second part
			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
			response=new byte[(byte)((numApp-19)*3)];
			for (byte i = 0; i < response.length; i=(byte)(i+3)) {
				byte[] AID=masterFile.getAID((byte)(i/3+21));//21 beacuase the IndexFile won't be included
				response[i]=AID[0];
				response[(byte)(i+1)]=AID[1];
				response[(byte)(i+2)]=AID[2];
			}
			sendResponse(apdu, buffer, response);
		}
	
		
		
	}
	
	/**
	 *	Get information on the PICC and application master key settings.
	 * 	In addition it returns the maximum number of keys which are configured for the selected application. 
	 */
	private void getKeySettings(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=0)ISOException.throwIt(Util.LENGTH_ERROR);
		if(!selectedDF.hasGetRights(authenticated))ISOException.throwIt(Util.PERMISSION_DENIED);
		byte ks=selectedDF.getKeySettings();
		byte kn=selectedDF.getKeyNumber();
		byte[] response=new byte[2];
		response[0]=ks;
		response[1]=kn;
		sendResponse(apdu, buffer, response);
	}
	
	/**
	 * Select one specific application for further access
	 * 
	 * @note || AID ||
	 */
	public void selectApplication(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=3)ISOException.throwIt(Util.LENGTH_ERROR);
		//AID
		byte[] AID = {buffer[ISO7816.OFFSET_CDATA],buffer[ISO7816.OFFSET_CDATA+1],buffer[ISO7816.OFFSET_CDATA+2]};
		if(javacard.framework.Util.arrayCompare(AID, (short)0, Util.masterFileAID,(short)0,(short) AID.length)== 0){
			selectedDF=masterFile;
		}else{
			byte i=masterFile.searchAID(AID);			
			if(i!=(byte)-1)	selectedDF=masterFile.arrayDF[masterFile.searchAID(AID)];
			else ISOException.throwIt(Util.APPLICATION_NOT_FOUND);
		}
		authenticated=Util.NO_KEY_AUTHENTICATED;
		securityLevel=Util.PLAIN_COMMUNICATION;
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/** 
	 * Releases the PICC user memory
	 * 
	 * @note 	Requires a preceding authentication with the PICC Master Key
	 * @effect	All application are deleted and all files within them. 
	 * 			The PICC Master Keyand the PICC Master Key settings keep their currently set values
	 */
	private void formatPICC(APDU apdu,byte[] buffer){
		if(selectedDF.isMasterFile()==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=0)ISOException.throwIt(Util.LENGTH_ERROR);
		if(masterFile.isFormatEnabled()==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		if(authenticated!=0)ISOException.throwIt(Util.PERMISSION_DENIED);
		masterFile.format();
		ISOException.throwIt(Util.OPERATION_OK);
		
	}
	
	/**
	 * Configures the card and pre personalizes the card with a key, defines if the UID or the 
	 * random ID is sent back during communication setup and configures the ATS string
	 * 
	 * 	@exception	Master key authentication on card level needs to be performed elsewise 
	 * 				throw PERMISSION_DENIED 
	 * 	@note		|| Option | ciphered( data || CRC )||
	 */
	private void setConfiguration(APDU apdu, byte[] buffer){
		if((selectedDF.isMasterFile()!=true)||(this.authenticated!=0)) ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if(((byte)buffer[ISO7816.OFFSET_LC]<9)&&((byte)buffer[ISO7816.OFFSET_LC]>33))ISOException.throwIt(Util.LENGTH_ERROR);
		
		//Gets the data
		byte encData[]=new byte[(byte)(buffer[ISO7816.OFFSET_LC]-1)];
		for (byte i = 0; i < encData.length; i++) {
			encData[i]=buffer[(byte)(i+ISO7816.OFFSET_CDATA+1)];
		}
		byte[] data =decrypt16(encData, sessionKey);
		
		//Checks the option
		switch(buffer[ISO7816.OFFSET_CDATA]){
		case (byte) 0x00: //Configuration byte
			masterFile.setConfiguration(data[0]);
			break;
		case (byte) 0x01://Default key version and default key
			byte[] keyBytes=new byte[(byte)(data.length-1)];
			//PARA LOS DISTINTOS TIPOS DE CLAVES PUEDEN COGERSE 8-16-24 BYTES DESDE LA IZQUIERDA
			//FALTA
			for (byte i = 0; i < 8; i++) {//When the key is 3DES
				keyBytes[i]=data[i];
			}
			masterFile.setDefaultKey(keyBytes);
			break;
		case (byte) 0x02://Data is the user defined ATS
			//FALTA
			break;
		default:
			ISOException.throwIt(Util.PARAMETER_ERROR);
			
		}
	}
	
	/**
	 * Returns the File Identifiers of all active files within the currently selected application
	 */
	private void getFileIDs(APDU apdu, byte[] buffer){
		if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=0)ISOException.throwIt(Util.LENGTH_ERROR);
		if(selectedDF.hasGetRights(authenticated))ISOException.throwIt(Util.PERMISSION_DENIED);
		byte[] IDs=new byte[selectedDF.getNumberFiles()+1];
		byte mark=0;
		for (byte i = 0; i < (byte)(IDs.length-1); i++) {
			for (byte j = mark; j < 32; j++) {
				if(selectedDF.activatedFiles[j]==true){
					selectedFile=selectedDF.getFile(j);
					selectedFile.getFileID();
					IDs[i]=selectedFile.getFileID();
					mark=(byte)(j+1);
					break;
				}
			}
		}
		IDs[(byte)IDs.length-1]=(byte)0x00;
		sendResponse(apdu,buffer,IDs);
	}

	/**
	 * 	Creates files for the storage and manipulation of 32bit signed 
	 * 	integer values within an existing application on the PICC
	 * 
	 * 	@note	|| FileN | CommunicationSetting | AccessRights | LowerLimit(4) | UpperLimit(4) | Value(4) | LimitedCreditEnabled ||
	 *               1                1                 2             4               4             4                  1 			
	 */
	public void createValueFile(APDU apdu, byte[] buffer){
		
	// checks if current directory is master file, if true aborts
	//  if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
	// if the lenght of the data is not 17 aborts
		if((byte)buffer[ISO7816.OFFSET_LC]!=17)ISOException.throwIt(Util.LENGTH_ERROR);
	// gers fileID
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
	// if fileID already exist in current directory then aborts
		if(selectedDF.isValidFileNumber(fileID)==true) ISOException.throwIt(Util.DUPLICATE_ERROR);
	// gets communication settings
		byte communicationSettings=(byte)buffer[ISO7816.OFFSET_CDATA+1];
	// gets access permissions
		byte[] accessPermissions={(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2]};
	// uses value construct to creat lowelimit, upperlimit and value since they are all 4 byte long
		Value lowerLimit= new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+7],(byte)buffer[ISO7816.OFFSET_CDATA+6],(byte)buffer[ISO7816.OFFSET_CDATA+5],(byte)buffer[ISO7816.OFFSET_CDATA+4]});
		Value upperLimit= new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+11],(byte)buffer[ISO7816.OFFSET_CDATA+10],(byte)buffer[ISO7816.OFFSET_CDATA+9],(byte)buffer[ISO7816.OFFSET_CDATA+8]});
		Value value=new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+15],(byte)buffer[ISO7816.OFFSET_CDATA+14],(byte)buffer[ISO7816.OFFSET_CDATA+13],(byte)buffer[ISO7816.OFFSET_CDATA+12]});
	// checks if upperLimit is not greater thatn lowe limit
		if(upperLimit.compareTo(lowerLimit)!=1)ISOException.throwIt(Util.BOUNDARY_ERROR);
	// checks if upperLimit is greater that initial value
		if(upperLimit.compareTo(value)!=1)ISOException.throwIt(Util.BOUNDARY_ERROR);
	// checks that value is greater that lowerLimit
		if(value.compareTo(lowerLimit)!=1)ISOException.throwIt(Util.BOUNDARY_ERROR);
	// gets limiteCredit
		byte limitedCreditEnabled=(byte)buffer[ISO7816.OFFSET_CDATA+16];
	// checks if memory is sufficient and ???
		if((short)(30)>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))ISOException.throwIt(Util.OUT_OF_EEPROM_ERROR);
	// security check on current directory i.e. if not autheticated file cant be created
	//	if(selectedDF.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
	//
		selectedFile=new ValueRecord(fileID, masterFile.arrayDF[selectedDF.getFileID()], communicationSettings, accessPermissions,lowerLimit,upperLimit,value,limitedCreditEnabled);
		selectedDF=masterFile.arrayDF[selectedDF.getFileID()];
		ISOException.throwIt(Util.OPERATION_OK);	
	}
	
	/**
	 * 	Permanently desactivates a file within the file directory of the
	 * 	currently selected application
	 * 
	 * 	@note	|| FileNumber || 	
	 *                  1
	 */
	private void deleteFile(APDU apdu, byte[] buffer){
		if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=1)ISOException.throwIt(Util.LENGTH_ERROR);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		if(selectedDF.isValidFileNumber(fileID)==false) ISOException.throwIt(Util.FILE_NOT_FOUND);
		if(selectedDF.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		selectedDF.deleteFile(fileID);
		masterFile.arrayDF[selectedDF.getFileID()]=selectedDF;
		ISOException.throwIt(Util.OPERATION_OK);
	}

	/**
	 * 	Reads the currently stored value form Value Files
	 * 
	 * 	@note	|| FileN ||	 
	 * 				 1
	 */
	public void getValue(APDU apdu, byte[] buffer){
		

		if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=1)ISOException.throwIt(Util.LENGTH_ERROR);
		byte fileID=buffer[ISO7816.OFFSET_CDATA];
		if(selectedDF.isValidFileNumber(fileID)==false) ISOException.throwIt(Util.FILE_NOT_FOUND);
		selectedFile=(ValueRecord)selectedDF.getFile(fileID);
		if(((ValueRecord)selectedFile).hasReadAccess(authenticated)!=true) ISOException.throwIt(Util.PERMISSION_DENIED);
		byte[] response=Util.switchBytes((((ValueRecord)selectedFile).getValue().getValue()));
		sendResponse(apdu, buffer, response,Util.OPERATION_OK,selectedFile.getCommunicationSettings());
//			short le = apdu.setOutgoing();
//			if(response.length==0)ISOException.throwIt( (short)0x917E);//AUX
//			
//			
//			apdu.setOutgoingLength( (short) response.length );
//			for (byte i = 0; i < response.length; i++) {
//				buffer[i]=response[i];
//			}
//			apdu.sendBytes ( (short)0 , (short)response.length );
	}
	
	/**
	 * 	Increases a value stored in a Value File
	 * 
	 * 	@note	||	FileN | Data  || 	
	 *                1       4
	 */ 
	
	public void credit(APDU apdu, byte[] buffer){
		if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=5)ISOException.throwIt(Util.LENGTH_ERROR);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		if(selectedDF.isValidFileNumber(fileID)==false) ISOException.throwIt(Util.FILE_NOT_FOUND);
		selectedFile=(ValueRecord)selectedDF.getFile(fileID);
		if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		((ValueRecord)selectedFile).addCredit(new Value(new byte[] {(byte)buffer[ISO7816.OFFSET_CDATA+4],(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2],(byte)buffer[ISO7816.OFFSET_CDATA+1]}));
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Decreases a value stored in a Value File
	 * 
	 * @note	||	FileN | Data  || 	
	 */
	public void debit(APDU apdu, byte[] buffer){
		if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=5)ISOException.throwIt(Util.LENGTH_ERROR);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		if(selectedDF.isValidFileNumber(fileID)==false) ISOException.throwIt(Util.FILE_NOT_FOUND);
		selectedFile=(ValueRecord)selectedDF.getFile(fileID);
		if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		((ValueRecord)selectedFile).decDebit(new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+4],(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2],(byte)buffer[ISO7816.OFFSET_CDATA+1]}));
		ISOException.throwIt(Util.OPERATION_OK);
		
	}
	
	/**
	 * 	Validates all previous write access on Backup Data Files, Value Files and 
	 * 	Record Files within one application 
	 */
	private void commitTransaction(APDU apdu, byte[] buffer){
		if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
	
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=0)ISOException.throwIt(Util.LENGTH_ERROR);
		for (byte i = 0; i < 32; i++) {
			if(selectedDF.getWaitingForTransaction(i)==true){
//				if(selectedDF.getFile(i) instanceof BackupFile){
//					selectedFile=(BackupFile)selectedDF.getFile(i);
//					if(((BackupFile)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
//					((BackupFile)selectedFile).commitTransaction();
//				}
//				if(selectedDF.getFile(i) instanceof LinearRecord){
//					selectedFile=(LinearRecord)selectedDF.getFile(i);
//					if(((LinearRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
//					((LinearRecord)selectedFile).commitTransaction();
//				}
//				if(selectedDF.getFile(i)instanceof CyclicRecord){
//					selectedFile=(CyclicRecord) selectedDF.getFile(i);
//					if(((CyclicRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
//					((CyclicRecord)selectedFile).commitTransaction();
//				}
				if(selectedDF.getFile(i)instanceof ValueRecord){
					selectedFile=(ValueRecord)selectedDF.getFile(i);
					if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((ValueRecord)selectedFile).commitTransaction();
				}
			}
		}
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Invalidates all previous write access on Backup Data Files, Value Files and 
	 * 	Record Files within one application
	 */
	private void abortTransaction(APDU apdu,byte[] buffer){
		if(selectedDF.isMasterFile()==true)ISOException.throwIt(Util.PERMISSION_DENIED);
		receiveAPDU(apdu, buffer);
		if((byte)buffer[ISO7816.OFFSET_LC]!=0)ISOException.throwIt(Util.LENGTH_ERROR);
		for (byte i = 0; i < 32; i++) {
			if(selectedDF.getWaitingForTransaction(i)==true){
//				if(selectedDF.getFile(i) instanceof BackupFile){
//					selectedFile=(BackupFile)selectedDF.getFile(i);
//					if(((BackupFile)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
//					((BackupFile)selectedFile).abortTransaction();
//				}
//				if(selectedDF.getFile(i) instanceof LinearRecord){
//					selectedFile=(LinearRecord)selectedDF.getFile(i);
//					if(((LinearRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
//					((LinearRecord)selectedFile).abortTransaction();
//				}
//				if(selectedDF.getFile(i) instanceof CyclicRecord){
//					selectedFile=(CyclicRecord) selectedDF.getFile(i);
//					if(((CyclicRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
//					((CyclicRecord)selectedFile).abortTransaction();
//				}
				if(selectedDF.getFile(i) instanceof ValueRecord){
					selectedFile=(ValueRecord)selectedDF.getFile(i);
					if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((ValueRecord)selectedFile).abortTransaction();
				}
			}
		}
	}
	
	/**
	 * 	Encrypts the message
	 * 
	 * 	@return 	The message encrypted in the following way:
	 * 				- The CRC16 is calculated
	 * 				- The whole array is padded
	 * 				- Everything is encyphered
	 * 	@note 	For the moment it only uses 3DES
	 */
	private byte[] encrypt16(byte[]msg,Key key) {
		
		//CRC16
		byte[] crc=Util.crc16(msg);//16-bit
		msg=Util.concatByteArray(msg, crc);
		//padding
		msg=Util.preparePaddedByteArray(msg);
		//Encypher		
		cipher.init(key, Cipher.MODE_ENCRYPT);
		cipher.doFinal(msg,(short)0,(short)msg.length, msg , (short)0);
		return msg;
	}
	
	/**
	 * 	Decrypts the message
	 * 
	 * 	@return The message decrypted in the following way:
	 * 				- Everything is decyphered
	 * 				- The padding is taken out				
	 * 				- The CRC16 is calculated and compared with the received
	 * 	@note 	For the moment it only uses 3DES
	 */
	private byte[] decrypt16(byte[] encryptedMsg,Key key){
		byte[]msg=new byte[encryptedMsg.length];
		try{
			//Decrypt
			cipher.init(key, Cipher.MODE_DECRYPT);
			cipher.doFinal(encryptedMsg,(short) 0,(short)encryptedMsg.length, msg, (short)0);
			//Padding out
			byte[] data=Util.removePadding(msg);
			//Checks CRC
			byte[] receivedCrc=Util.subByteArray(data, (byte)(data.length-2),(byte) (data.length-1));
			data=Util.subByteArray(data,(byte) 0, (byte)(data.length-3));
			byte[] newCrc=Util.crc16(data);
			if(Util.byteArrayCompare(newCrc,receivedCrc)==false){
				//We check if there was no padding
				receivedCrc=Util.subByteArray(msg, (byte)(msg.length-2),(byte) (msg.length-1));
				msg=Util.subByteArray(msg,(byte) 0, (byte)(msg.length-3));
				newCrc=Util.crc16(msg);
				if(Util.byteArrayCompare(newCrc,receivedCrc)==false){
					securityLevel=Util.PLAIN_COMMUNICATION;
					ISOException.throwIt(Util.INTEGRITY_ERROR);
				}
				return msg;
			}
			return data;
		}catch ( CryptoException e){
			securityLevel=Util.PLAIN_COMMUNICATION;
			ISOException.throwIt(Util.INTEGRITY_ERROR);	
		}
		return null;		
	}

	/**
	 * Returns the plain data of the APDU 
	 */
	private byte[] getCData(byte[] cData){
		switch(this.securityLevel){
			case Util.PLAIN_COMMUNICATION:
				return cData;
			case Util.FULLY_ENCRYPTED:
				if(cData.length>0){
					cData=decrypt16(cData,sessionKey);
					return cData;
				}
				else return cData;
				
			default:
				break;
		}
		return null;
	}

	/**
	 * 
	 */
	private void receiveAPDU(APDU apdu, byte[] buffer){
		// Lc tells us the incoming apdu command length
		  short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		  short readCount = apdu.setIncomingAndReceive();
		  while ( bytesLeft > 0){
		      // process bytes in buffer[5] to buffer[readCount+4];
		      bytesLeft -= readCount;
		      readCount = apdu.receiveBytes ( ISO7816.OFFSET_CDATA );
		      }		
		  byte[] cData=getCData(Util.subByteArray(buffer,(byte)ISO7816.OFFSET_CDATA,(byte)(ISO7816.OFFSET_CDATA+buffer[ISO7816.OFFSET_LC]-1)));
		  
		buffer=Util.copyByteArray(cData, (short) 0, (short)cData.length,buffer, (short)ISO7816.OFFSET_CDATA);
		buffer[ISO7816.OFFSET_LC]=(byte) cData.length;
		  
	}

	/**
	 * 
	 */
	private void sendResponse(APDU apdu, byte[] buffer,byte[] response){
		sendResponse(apdu,buffer,response,(byte)0x00);
	}
	
	/**
	 * Send a response with configurable status word
	 */
	private void sendResponse(APDU apdu, byte[] buffer,byte[] response, short status){
		sendResponse(apdu, buffer, response, status, this.securityLevel);
	}
	
	/**
	 * 	Send a response with configurable status word and security level	
	 */
	private void sendResponse(APDU apdu, byte[] buffer,byte[] response, short status,byte securityLevel){
		// construct the reply APDU
		try{
			short le = apdu.setOutgoing();
			// if (le < (short)2) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
			if(response.length==0)ISOException.throwIt( (short)0x917E);//AUX
	//			this.securityLevel=Util.PLAIN_COMMUNICATION;
			// build response data in apdu.buffer[ 0.. outCount-1 ];
			switch (securityLevel) {
			case Util.PLAIN_COMMUNICATION:
				break;
			case Util.PLAIN_COMMUNICATION_MAC:		
				break;
			case Util.FULLY_ENCRYPTED:
				response=encrypt16(response,sessionKey);
				break;
			default:
				break;
			}
			apdu.setOutgoingLength( (short) response.length );
			for (byte i = 0; i < response.length; i++) {
				buffer[i]=response[i];
			}
			apdu.sendBytes ( (short)0 , (short)response.length );
		}catch (APDUException e) {
				ISOException.throwIt(e.getReason());
		}
		return;	
	}
	
	
	
	/**
		 * This is needed for the authentication because the last message should be sended 
		 * encrypted with the old session key and afterwards the session key should change 
		 */
		private void sendResponseAndChangeStatus(APDU apdu, byte[] buffer,byte[] response,byte[] newSessionKey){
			
			// construct the reply APDU
			short le = apdu.setOutgoing();
			// if (le < (short)2) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
			if(response.length==0)ISOException.throwIt( (short)0x917E);//AUX
	//			this.securityLevel=Util.PLAIN_COMMUNICATION;
			// build response data in apdu.buffer[ 0.. outCount-1 ];
			switch (this.securityLevel) {
			case Util.PLAIN_COMMUNICATION:
				break;
			case Util.PLAIN_COMMUNICATION_MAC:		
				break;
			case Util.FULLY_ENCRYPTED:
				response=encrypt16(response,sessionKey);
				break;
			default:
				break;
			}
			sessionKey.clearKey();
			((DESKey)sessionKey).setKey(newSessionKey, (byte)0);
			securityLevel=Util.FULLY_ENCRYPTED;
			apdu.setOutgoingLength( (short) response.length );
			for (byte i = 0; i < response.length; i++) {
				buffer[i]=response[i];
			}
			apdu.sendBytes ( (short)0 , (short)response.length );
			return;
		}

	/**
	 * 	Initialize the applet when it is selected, select always 
	 * 	has to happen after a reset
	 */
	public boolean select(boolean appInstAlreadyActive){
		// clear();
		return true;
	}
	
	/**
	 * 	Perform any cleanup tasks before the applet is deselected
	 */
	public void deselect(boolean appInstStillActive){
//		clear();
		return;
	}
	
	/**
	 * 	Perform any cleanup tasks and set the PICC level
	 */
	private void clear(){
		selectedFile=null;
		selectedDF=masterFile;
		commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
		authenticated=Util.NO_KEY_AUTHENTICATED;
		//dataBuffer=null;
		securityLevel=Util.PLAIN_COMMUNICATION;
		fileSecurityLevel=Util.PLAIN_COMMUNICATION;
//		readed=0;
//		offset=0;
//		bytesLeft=0;
		keyNumberToAuthenticate=0;
		sessionKey.clearKey();	
	}
	
	/**
	 * 		Decrypts the key data for some commands that require this particular
	 * 	security mechanism
	 * 
	 * 	@note	If the key number to change is different from the key used for authentication,
	 * 			it is needed to prove that the other key is also known so the PCD has to:
	 * 				- bit-wise XOR both new and old key
	 * 				- calculate CRC16 over the XOred data and append it to the end
	 * 
	 * 	@note 	The key to be change is enciphered by the PCD in the next way:
	 * 				- append at the end the CRC16 calculated over the new key
	 * 				- Do the paddingto reach an adequate frame size
	 * 				- Encipher using he current session key
	 * 				- The blocks are chained in CRC send mode.
	 */
	public byte[] decryptEncipheredKeyData(byte[] encipheredData, byte keyN){
		
		if(keyN==authenticated){
			return decrypt16(encipheredData, sessionKey);
		} else{
			//Decrypt
			byte[] unpaddedData=new byte[encipheredData.length];
			cipher.init(sessionKey, Cipher.MODE_DECRYPT);
			cipher.doFinal(encipheredData,(short) 0,(short)encipheredData.length, unpaddedData, (short)0);
			
			//Padding out
			byte[] data=Util.removePadding(unpaddedData);
			
			//Checks CRC
			byte[] receivedNewKeyCrc=Util.subByteArray(data, (byte)(data.length-2),(byte) (data.length-1));
			byte[] receivedXORCrc=Util.subByteArray(data, (byte)(data.length-4),(byte) (data.length-3));
			data=Util.subByteArray(data,(byte) 0, (byte)(data.length-5));
			byte[] XORCrc=Util.crc16(data);
			if(Util.byteArrayCompare(XORCrc,receivedXORCrc)==false){
				//We check if there was no padding
				receivedXORCrc=Util.subByteArray(unpaddedData,(byte)(unpaddedData.length-4),(byte) (unpaddedData.length-3));
				data=Util.subByteArray(unpaddedData,(byte) 0, (byte)(unpaddedData.length-5));
				XORCrc=Util.crc16(data);
				if(Util.byteArrayCompare(XORCrc,receivedXORCrc)==false){
					securityLevel=Util.PLAIN_COMMUNICATION;
					ISOException.throwIt(Util.INTEGRITY_ERROR);
				}	
			}
			
			//The new key is obtained
			byte[] oldKey=new byte[16];
			try{
				((DESKey)selectedDF.getKey(keyN)).getKey(oldKey, (short)0);
			}catch (ISOException e) {
				oldKey=Util.getZeroArray((short) 16);
			}
			byte[] newKey=Util.xorByteArray(data,oldKey);
			
			//Check the CRC of the new key
			byte[] newKeyCrc=Util.crc16(newKey);
			if(Util.byteArrayCompare(newKeyCrc,receivedNewKeyCrc)==false){
				//We check if there was no padding
				receivedNewKeyCrc=Util.subByteArray(unpaddedData,(byte)(unpaddedData.length-2),(byte) (unpaddedData.length-1));
				data=Util.subByteArray(unpaddedData,(byte) 0, (byte)(unpaddedData.length-3));
				newKey=Util.xorByteArray(data,oldKey);
				newKeyCrc=Util.crc16(newKey);
				if(Util.byteArrayCompare(newKeyCrc,receivedNewKeyCrc)==false){
					securityLevel=Util.PLAIN_COMMUNICATION;
					ISOException.throwIt(Util.INTEGRITY_ERROR);
				}	
			}
			
			//If no exception is thrown the new key is returned
			return newKey;
		}		
	}

	// TEST CODE
	public void getBalance(APDU apdu, byte[] buffer) {
//		 inform the JCRE that the applet has data to return
		short le = apdu.setOutgoing();
 
		// set the actual number of the outgoing data bytes
		apdu.setOutgoingLength((byte)2);
 
 
		// write the balance into the APDU buffer at the offset 0
		javacard.framework.Util.setShort(buffer, (short)0, (balance));
 
		// send the 2-byte balance at the offset
		// 0 in the apdu buffer
		apdu.sendBytes((short)0, (short)2);
		
	}
	
}



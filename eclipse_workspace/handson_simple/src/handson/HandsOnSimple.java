/*
 *
 * Package:  handson
 * Filename: HandsOnSimple.java
 * Class:    HandsOnSimple
 * Date:     24.08.2005
 * Author:	 Ivan Plajh
 *
 *
****************************************************************************
* HandsOn training 
*	------------------------------------------------------------
*   First Applet
*	- structure definition
*	- tool functionality examination
*	------------------------------------------------------------
****************************************************************************
 */

package handson;

import javacard.framework.*;

/**
 *
 * Class HandsOn
 *
 */

public class HandsOnSimple extends javacard.framework.Applet
{
    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        (new HandsOnSimple()).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        
		if ( selectingApplet() )
        {
            return;
        }

        if ( (buf[ISO7816.OFFSET_CLA] != 0) || (buf[ISO7816.OFFSET_INS] != (byte)(0xAA)) )
        {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        
		switch ( buf[ISO7816.OFFSET_P1] )
        {
            case (byte)0x01 :
                Util.setShort(buf, (short)0, (short)2);
                apdu.setOutgoingAndSend((short)0, (short)5);
                return;
        }
    }
}

/*
* TASK FOR YOU: 
*------------------------------------------------------------
*   Modify the AID of the applet
*   Run the project in JCOP41 Simulator
*	Examine the functionality of the JC Shell
*		- delete the instance JCOP Tools have created automatically (command: delete)
*		- delete the package
*		- reset the card (command: /atr)
*		- perform mutual authentication
*		- upload the package manually
*		- install the applet
*		- modify and run the script simple.jcsh
*------------------------------------------------------------
*
* TIPS:
*------------------------------------------------------------
*   Use Help > Help Contents > JCOP Tools User Guide
*------------------------------------------------------------
*/

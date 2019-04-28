import java.net.*;
import java.io.*;
import java.util.Arrays;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.text.SimpleDateFormat;
import java.text.MessageFormat;
import java.util.Date;


import java.io.PrintStream;
import java.io.PrintWriter;





class Clientthreaded extends Thread
{
	/*
	byte[] b = {
			(byte)0x0F,(byte)0xF4,(byte)0x75,(byte)0xF8,(byte)0x64,(byte)0x35,(byte)0xB7,(byte)0x44,
			(byte)0x2E,(byte)0x69,(byte)0x97,(byte)0xE5,(byte)0x0F,(byte)0x6C,(byte)0x93,(byte)0xEA,
			(byte)0xC0,(byte)0x1C,(byte)0x80,(byte)0x0B,(byte)0xB2,(byte)0xCE,(byte)0x9F,(byte)0x28,
			(byte)0x47,(byte)0x27,(byte)0xF8,(byte)0x32,(byte)0x07,(byte)0x2A,(byte)0x64,(byte)0xA8,
			(byte)0x8A,(byte)0x13,(byte)0x36,(byte)0xD9,(byte)0x9D,(byte)0xE1,(byte)0x3B,(byte)0xA6,
			(byte)0x0C,(byte)0x17,(byte)0x5B,(byte)0xD2,(byte)0xA9,(byte)0xF8,(byte)0x70,(byte)0x53,
			(byte)0x73,(byte)0xAC,(byte)0x75,(byte)0xEB,(byte)0xF6,(byte)0x38,(byte)0xF6,(byte)0xD0,
			(byte)0xE0,(byte)0x4B,(byte)0xFA,(byte)0x3D,(byte)0x61,(byte)0x50,(byte)0xB7,(byte)0x07,
			(byte)0x6D,(byte)0xDE,(byte)0xC7,(byte)0x6B,(byte)0x9A,(byte)0x46,(byte)0xBD,(byte)0xB7,
			(byte)0x83,(byte)0x44,(byte)0x9E,(byte)0x22,(byte)0x0A,(byte)0x72,(byte)0x64,(byte)0xA0 };*/
	  

   	byte[] iv = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x70,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
   			     (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x03
   			     };
   	
   	byte[] plain = {
   		 (byte)0x00,(byte)0x00,(byte)0x4b,(byte)0xd6,(byte)0x47,(byte)0x4d,(byte)0x18,(byte)0xdc,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0xff,(byte)0x00,(byte)0x00
   		,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x08,(byte)0x00,(byte)0x14
   		,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
   		,(byte)0x03,(byte)0x07,(byte)0x84,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x70,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x03

   	};
   	
   	
   	byte[] key = {(byte)0x18,(byte)0xD8,(byte)0xBE,(byte)0x64,(byte)0xC2,(byte)0xBE,(byte)0x96,(byte)0x6D,
   			       (byte)0x41,(byte)0x29,(byte)0x05,(byte)0xAD,(byte)0x54,(byte)0xFA,(byte)0x27,(byte)0x85};
	
	
	byte[] i;
	byte[] cipher  = new byte[80];
    // initialize socket and input output streams

    
    public String address1 = "";
    public int port1;
    
    private Socket socket            = null;
    private DataInputStream  input   = null;
    private DataOutputStream output     = null;
    
    // constructor to put ip address and port
    public Clientthreaded(String address, int port)
    {
       address1 = address;
       port1 = port;
    }
    
    
    public static byte[] encrypt(byte[] key, byte[] initVector, byte[] value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            
            GCMParameterSpec spec = new GCMParameterSpec(16 * 8, initVector);
            
            
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec , spec);

            byte[] encrypted = cipher.doFinal(value);
            //System.out.println("encrypted string: ",encrypted);

            return encrypted;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static void incrementAtIndex(byte[] array, int index) {
        if (array[index] == 0x7f) 
        {
            array[index] = 0;
            if(index > 0)
                incrementAtIndex(array, index - 1);
        }
        else {
            array[index]++;
        }
    }
    
    public static byte[] decrypt(byte[] key, byte[] initVector, byte[] encrypted) {
        try {
        	
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/Nopadding");
            
            GCMParameterSpec spec = new GCMParameterSpec(16 * 8, initVector );
            
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, spec);

            byte[] original = cipher.doFinal(encrypted, 0, encrypted.length);

            return original;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
    
    public static void hexDump(PrintStream out, byte[] data)
    {
      if (out == null)
         return;

      if (data == null)
      {
         out.println("Null");
         return;
      }

      // Dump the bytes in 'data'
      hexDumpAt(new PrintWriter(out, false), data, 0, data.length,0);
    }

    /****************************************************
     * Dump byte buffer in hexadecimal format
     ****************************************************/

    public static void hexDumpAt(PrintWriter out, byte[] data,
                                 int off, int len, int base)
    {
      int   loc;
      int   end;

      out.println("");

      // Print a hexadecimal dump of 'data[off...off+len-1]'
      if (off >= data.length)
         off = data.length;

      end = off+len;
      if (end >= data.length)
         end = data.length;

      len = end-off;
      if (len <= 0)
         return;

      loc = (off/0x10)*0x10;

      for (int i = loc;  i < end;  i += 0x10, loc += 0x10)
      {
         int j;
         // Print the location/offset
         {
            int v;
            v = base+loc;
            for (j = (8-1)*4;  j >= 0;   j -= 4)
            {
               int d;
               d = (v >>> j) & 0x0F;
               d = (d < 0xA ? d+'0' : d-0xA+'A');
               out.print((char) d);
            }
         }

         // Print a row of hex bytes
         out.print("  ");
         for (j = 0x00;  i+j < off;  j++)
            out.print(".. ");

         for ( ;  j < 0x10  &&  i+j < end;  j++)
         {
            int ch;
            int d;
            if (j == 0x08)
               out.print(' ');

            ch = data[i+j] & 0xFF;
            d = (ch >>> 4);
            d = (d < 0xA ? d+'0' : d-0xA+'A');
            out.print((char) d);

            d = (ch & 0x0F);
            d = (d < 0xA ? d+'0' : d-0xA+'A');
            out.print((char) d);

            out.print(' ');
         }

         for ( ;  j < 0x10;  j++)
         {
            if (j == 0x08)
               out.print(' ');

            out.print(".. ");
         }

         // Print a row of printable characters
         out.print(" |");

         for (j = 0x00;  i+j < off;  j++)
            out.print(' ');

         for ( ;  j < 0x10  &&  i+j < end;  j++)
         {
            int ch;
            ch = data[i+j] & 0xFF;

            if (ch < 0x20  ||
                   ch >= 0x7F  &&  ch < 0xA0  ||
                     ch > 0xFF)
            {
               // The character is unprintable
               ch = '.';
            }

            out.print((char) ch);

         }

         for ( ;  j < 0x10;  j++)
            out.print(' ');


         //out.println("|");

      }
      out.println("");

      
      out.flush();
    }
    
    
    public void run()
    {
    	
    	 // establish a connection./
        try
        {
            this.socket = new Socket(address1, port1);
            System.out.println("Connected");

            this.input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

            // sends output to the socket
            this.output    = new DataOutputStream(socket.getOutputStream());
        }
        catch(UnknownHostException u)
        {
            System.out.println(u);
        }
        catch(IOException i)
        {
            System.out.println(i);
        }

        byte[] localIV;
		localIV = iv;
        
        for(int i = 0; i < 30; i++ )
        {
        	try
        	{
        
        		        		
        	    byte[] b = encrypt(key, localIV, plain);
        		
        	    
        		System.out.println("Writing in buffer to server");
        		System.out.println(b.length);
        		hexDump(System.out, b);
        		output.write(b, 0, b.length);
        
        		System.out.println("reading buffer from server");
        		input.read(cipher, 0, 80);
        		hexDump(System.out, cipher);
        		
        		byte[] pt =  decrypt(key, localIV, cipher);
        		hexDump(System.out, pt);
        		
        		incrementAtIndex(localIV, 11);
            
        	}
        	catch(IOException ioe)
        	{ 
        		System.out.println("Sending error: " + ioe.getMessage());
        	}
        }
  

        try
        {
        	 input.close();
             output.close();
             socket.close();
         }
         catch(IOException i)
         {
             System.out.println(i);
         }
    }

 }


public class Client
{

    public static void main(String args[])
    {
    	for(int i = 0; i < 50; i++)
    	{
            Clientthreaded client1 = new Clientthreaded("153.64.238.146", 5001);
            client1.start();
    	}
    }
}

        
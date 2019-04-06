package Cliente;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Digest {
	public static byte[] getDigest(String algoritmo, byte[] buffer)
	{
		MessageDigest digest;
		try
		{
			digest = MessageDigest.getInstance(algoritmo);
			digest.update(buffer);
			return digest.digest();
		} 
		catch (NoSuchAlgorithmException e) 
		{
			return null;
		}
	}
	public static byte[] getByte(String algoritmo, byte[] buffer)
	{
		MessageDigest digest;
		try
		{
			digest = MessageDigest.getInstance(algoritmo);
			//TODO
			return null;
		} 
		catch (NoSuchAlgorithmException e) 
		{
			return null;
		}
	}
	public static void imprimirHexa(byte[] contenido)
	{
		String out = "";
		System.out.println("-------------------------------------------------------------");
		for(int i = 0;i<contenido.length;i++)
		{
			if((contenido[i] & 0xff)<=0xf)
				out+="0";
			out+= Integer.toHexString(contenido[i] & 0xff).toLowerCase();
		}
		System.out.print(out+"\n");
	}
}

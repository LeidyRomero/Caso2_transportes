package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

public class ConSeguridad {
	private static int PUERTO = 8000;
	public static final String SERVIDOR = "localhost";
	
	public static final String HOLA = "HOLA";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String OK = "OK";
	public static final String SEPARADOR = ":";
	public static final String AES = "AES";
	public static final String RSA = "RSA";
	public static final String HMACSHA1 = "HMACSHA1";
		
	public static void main(String args[]) throws Exception
	{
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		System.out.println("Unidad de distribución");

		try 
		{
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (IOException e) {
			System.err.println("Exception: "+e.getMessage());
			System.exit(1);
		}

		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		
		String algoritmos = "ALGORITMOS:";
		algoritmos+= AES+":"+RSA+":"+HMACSHA1;
		
		try {
			Protocolo.procesar(algoritmos,stdIn,lector,escritor);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en el procesamiento");
		}
		
		escritor.close();
		lector.close();
		socket.close();
		stdIn.close();
	}

}

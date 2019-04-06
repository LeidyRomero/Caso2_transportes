package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.operator.OperatorCreationException;

public class ConSeguridad {
	private static int PUERTO = 8000;
	public static final String SERVIDOR = "localhost";
	public final static String[] ALGORITMOS_SIMETRICOS = {"AES","Blowfish"};
	public final static String ALGORITMO_ASIMETRICO = "RSA";
	public final static String[] ALGORITMOS_HMAC = {"HMACSHA1","HMACSHA256","HMACSHA384","HMACSHA512"};
	
	public static void main(String args[]) throws IOException, OperatorCreationException, CertificateException
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
		int RandomSimetricos = (int) Math.random()*ALGORITMOS_SIMETRICOS.length;
		int RandomHmac = (int) Math.random()*ALGORITMOS_HMAC.length;
		algoritmos+= ALGORITMOS_SIMETRICOS[RandomSimetricos]+":"+ALGORITMO_ASIMETRICO+":"+ALGORITMOS_HMAC[RandomHmac];
		
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

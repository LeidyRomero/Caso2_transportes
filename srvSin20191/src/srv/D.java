package srv;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class D extends Thread {
	public static final String OK = "OK";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String CERTSRV = "CERTSRV";
	public static final String CERCLNT = "CERCLNT";
	public static final String SEPARADOR = ":";
	public static final String HOLA = "HOLA";
	public static final String INICIO = "INICIO";
	public static final String ERROR = "ERROR";
	public static final String REC = "recibio-";
	public static final String DES = "DES";
	public static final String AES = "AES";
	public static final String BLOWFISH = "Blowfish";
	public static final String RSA = "RSA";
	public static final String ECIES = "ECIES";
	public static final String RC4 = "RC4";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String HMACSHA384 = "HMACSHA384";
	public static final String HMACSHA512 = "HMACSHA512";

	// Atributos
	private Socket sc = null;
	private String dlg;
	private byte[] mybyte;
	private static X509Certificate certSer;
	private static KeyPair keyPairServidor;
	
	public D (Socket csP, int idP) {
		sc = csP;
		dlg = new String("delegado sin" + idP + ": ");
		try {
		mybyte = new byte[520]; 
		mybyte = certSer.getEncoded( );
		} catch (Exception e) {
			System.out.println("Error creando encoded del certificado para el thread" + dlg);
			e.printStackTrace();
		}
	}
	
	public static void initCertificate(X509Certificate pCertSer, KeyPair pKeyPairServidor) {
		certSer = pCertSer;
		keyPairServidor = pKeyPairServidor;
	}
	
	private boolean validoAlgHMAC(String nombre) {
		return ((nombre.equals(HMACMD5) || 
			 nombre.equals(HMACSHA1) ||
			 nombre.equals(HMACSHA256) ||
			 nombre.equals(HMACSHA384) ||
			 nombre.equals(HMACSHA512)
			 ));
	}

	public void run() {
		String linea;
	    System.out.println(dlg + "Empezando atencion.");
	        try {

				PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
				BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));

				/***** Fase 1:  *****/
				linea = dc.readLine();
				if (!linea.equals(HOLA)) {
					ac.println(ERROR);
				    sc.close();
					throw new Exception(dlg + ERROR + REC + linea +"-terminando.");
				} else {
					ac.println(OK);
					System.out.println(dlg + REC + linea + "-continuando.");
				}
				
				/***** Fase 2:  *****/
				linea = dc.readLine();
				if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals(ALGORITMOS))) {
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + REC + linea +"-terminando.");
				}
				
				String[] algoritmos = linea.split(SEPARADOR);
				if (!algoritmos[1].equals(DES) && !algoritmos[1].equals(AES) &&
					!algoritmos[1].equals(BLOWFISH) && !algoritmos[1].equals(RC4)){
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + "Alg.Simetrico" + REC + algoritmos + "-terminando.");
				}
				if (!algoritmos[2].equals(RSA) ) {
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + "Alg.Asimetrico." + REC + algoritmos + "-terminando.");
				}
				if (!validoAlgHMAC(algoritmos[3])) {
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + "AlgHash." + REC + algoritmos + "-terminando.");
				}
				System.out.println(dlg + REC + linea + "-continuando.");
				ac.println(OK);

				/***** Fase 3:  *****/				
				String strCertificadoCliente = dc.readLine();				
				byte[] certificadoClienteBytes = new byte[520];
				certificadoClienteBytes = toByteArray(strCertificadoCliente);
				CertificateFactory creador = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(certificadoClienteBytes);
				X509Certificate certificadoCliente = (X509Certificate)creador.generateCertificate(in);
				System.out.println(dlg + "recibio certificado del cliente. continuando.");
				//ac.println(OK);
				
				/***** Fase 4:  *****/
				ac.println(toHexString(mybyte));
				System.out.println(dlg + "envio certificado del servidor. continuando.");				

				/***** Fase 5: *****/
				linea = dc.readLine();
				byte[] llaveSimetrica = toByteArray(linea);
				System.out.println(dlg + "creo llave simetrica de dato recibido. continuando.");				
				
				
				//**** Fase 6:  *****

				ac.println(toHexString(llaveSimetrica));
				System.out.println(dlg + "envio llave simetrica al cliente. continuado.");

				linea = dc.readLine();
				if (!(linea.equals(OK))) {
					sc.close();
					throw new Exception(dlg + ERROR + "en confirmacion de llave simetrica." + REC + "-terminando.");
				}

				//**** Fase 7:  *****

				String datos1 = dc.readLine();				
				String datos2 = dc.readLine();
				

				//**** Fase 8:  *****
				boolean verificacion = datos1.equals(datos2);
				if (verificacion) {
					System.out.println(dlg + "verificacion de integridad:OK. -continuado.");
					ac.println(datos1);
				} else {
					ac.println(ERROR);
					throw new Exception(dlg + "Error en verificacion de integridad. -terminando.");
				}

		        sc.close();
		        System.out.println(dlg + "Termino exitosamente.");
				
	        } catch (Exception e) {
	        	try {
	        	    sc.close();
	        	} catch (Exception e2) { e2.printStackTrace(); }
	          e.printStackTrace();
	        }
	}
	
	public static String toHexString(byte[] array) {
	    return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
	    return DatatypeConverter.parseHexBinary(s);
	}
}

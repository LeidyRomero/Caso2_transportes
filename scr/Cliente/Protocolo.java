package Cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Protocolo {
	public static final String HOLA = "HOLA";
	public static final String ERROR = "ERROR";
	public static final String OK = "OK";
	public static final String SEPARADOR = ":";
	
	private static final String PADDING = "AES/ECB/PKCS5Padding";

	public static void procesar (String algoritmos,BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws Exception
	{
		pOut.println(HOLA);
		String fromServer = "";
		//Si no llega del servidor no es null
		if((fromServer = pIn.readLine())!= null && fromServer.equalsIgnoreCase(OK))
		{
			pOut.println(algoritmos);
			System.out.println("Cliente: "+algoritmos);
			fromServer = pIn.readLine();
			if((fromServer != null && fromServer.equalsIgnoreCase(OK)))
			{
				//llaves asimetricas con RSA
				KeyPairGenerator generator = KeyPairGenerator.getInstance(ConSeguridad.RSA);
				generator.initialize(1024);//inicializa el generador que va a crear llaves del tamaño que se envio como parametro
				KeyPair pareja = generator.generateKeyPair();
				PublicKey llavePublica = pareja.getPublic();
				PrivateKey llavePrivada = pareja.getPrivate();
				
				//Llave simetrica
				KeyGenerator keyGen = KeyGenerator.getInstance(ConSeguridad.AES);
				keyGen.init(128);
				SecretKey llaveSimetrica = keyGen.generateKey();
				//enviar certificado cliente

				X509Certificate certificadoCliente = generarCertificadoCliente(llavePublica,llavePrivada,ConSeguridad.HMACSHA1);
				byte[] certificadoEnBytes = certificadoCliente.getEncoded();
				String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
				pOut.println(certificadoEnString);
				System.out.println("Cliente: envía el certificado del cliente");

				X509Certificate certificadoServidor = recibirCertificadoServidor(pIn);
				System.out.println("Cliente: recibe el certificado del servidor");

				byte[] textoCifradoEnviar = cifrarAsimetrico(certificadoServidor.getPublicKey(),llaveSimetrica);
				System.out.println("Cliente: crea la llave simétrica");
				if(textoCifradoEnviar!= null) 
				{
					pOut.println(DatatypeConverter.printHexBinary(textoCifradoEnviar));
					System.out.println("Cliente: envía la llave simétrica");
				}
				if((fromServer = pIn.readLine())!= null)
				{
					System.out.println("Cliente: recibe llave simétrica del servidor");
					byte[] textoDescifrado = descifrarAsimetricoConLlavePrivada(fromServer, llavePrivada);
					boolean verificar = verificar(llaveSimetrica.getEncoded(), textoDescifrado);
					if(verificar)
					{
						pOut.println(OK);
						System.out.println("Cliente: verifica que la llave simétrica coincide");

						byte[] cifradoS = cifrarSimetrico(llaveSimetrica);
						pOut.println(DatatypeConverter.printHexBinary(cifradoS));
						System.out.println("Cliente: envía los datos cifrados");

						byte[] digest = hmac(ConSeguridad.HMACSHA1, llaveSimetrica);
						pOut.println(DatatypeConverter.printHexBinary(digest));
						System.out.println("Cliente: envía el hash de los datos");

						if((fromServer = pIn.readLine())!= null && !fromServer.equals(ERROR))
						{
							System.out.println("Cliente: recibe los datos cifrados por el servidor");
							byte[] rta = descifrarAsimetricoConLlavePublica(fromServer, certificadoServidor.getPublicKey());
							String aux1 = new String(rta);
							String aux2 = new String(digest);
							if(aux1.equals(aux2))
							{
								System.out.println("Cliente: termino exitosamente");
							}
						}
					}
					else {
						System.err.println("Exception: las llaves simétricas no coinciden");
						System.exit(1);
					}

				}
			}
			else if((fromServer = pIn.readLine())!= null && fromServer.equalsIgnoreCase(ERROR))
			{
				System.out.println("Error");
			}
		}	
	}
	/**
	 * CommonName : "Cliente"
	 * OrganizationaUnit : "Transportes"
	 * OrganizationName : "Compania transportadora"
	 * localityName locality (city) name: "Bogota"
	 * stateName state name : "Colombia"
	 * Country : "CO"
	 * @return 
	 * @throws CertIOException 
	 * @throws OperatorCreationException 
	 * @throws CertificateException 
	 */
	public static X509Certificate generarCertificadoCliente(PublicKey publica, PrivateKey privada, String algoritmo) throws CertIOException, OperatorCreationException, CertificateException
	{
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);

		Calendar endCalendar = Calendar.getInstance();
		endCalendar.add(1, 10);
		X509v3CertificateBuilder certBuilder = 
				new X509v3CertificateBuilder(new X500Name("CN=cliente"), 
						BigInteger.valueOf(1L), 
						Calendar.getInstance().getTime(), 
						endCalendar.getTime(), 
						new X500Name("CN=cliente"), 
						SubjectPublicKeyInfo.getInstance(publica.getEncoded()));
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA")
				.build(privada);

		// -------------------------------------
		return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
	}
	public static X509Certificate recibirCertificadoServidor(BufferedReader pIn) throws IOException, CertificateException
	{
		byte[] certificadoEnBytes = DatatypeConverter.parseHexBinary(pIn.readLine());
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		X509Certificate certificado = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificadoEnBytes));
		return certificado;
	}
	public static byte[] cifrarAsimetrico(PublicKey llavePublicaServidor, SecretKey llaveSimetrica)
	{
		try
		{
			Cipher cifrador = Cipher.getInstance(ConSeguridad.RSA);
			byte[] textoCifrado;
			cifrador.init(Cipher.ENCRYPT_MODE, llavePublicaServidor);
			textoCifrado = cifrador.doFinal(llaveSimetrica.getEncoded());

			return textoCifrado;
		}
		catch(Exception e)
		{
			System.out.println("Excepcion: "+e.getMessage());
			return null;
		}
	}
	public static byte[] cifrarSimetrico(SecretKey llaveSimetrica)
	{
		byte[] textoCifrado;
		try{

			Cipher cifrador = Cipher.getInstance(PADDING);
			byte[] textoClaro = "15;41 24.2028,2 10.4418".getBytes();

			cifrador.init(Cipher.ENCRYPT_MODE, llaveSimetrica);
			textoCifrado = cifrador.doFinal(textoClaro);

			return textoCifrado;
		}
		catch(Exception e)
		{
			System.out.println("Excpcion: " + e.getMessage());
			return null;
		}
	}
	public static byte[] descifrarAsimetricoConLlavePrivada(String fromServer, PrivateKey llavePrivadaCliente)
	{
		byte[] textoClaro;

		try
		{
			Cipher cifrador = Cipher.getInstance(ConSeguridad.RSA);
			cifrador.init(Cipher.DECRYPT_MODE, llavePrivadaCliente);
			textoClaro = cifrador.doFinal(DatatypeConverter.parseHexBinary(fromServer));
			return textoClaro;
		}
		catch(Exception e)
		{
			System.out.println("Excepcion: "+e.getMessage());
			return null;
		}
	}
	public static byte[] descifrarAsimetricoConLlavePublica(String fromServer, PublicKey llavePublicaCliente)
	{
		byte[] textoClaro;

		try
		{
			Cipher cifrador = Cipher.getInstance(ConSeguridad.RSA);
			cifrador.init(Cipher.DECRYPT_MODE, llavePublicaCliente);

			textoClaro = cifrador.doFinal(DatatypeConverter.parseHexBinary(fromServer));
			return textoClaro;
		}
		catch(Exception e)
		{
			System.out.println("Excepcion: "+e.getMessage());
			return null;
		}
	}
	public static byte[] hmac(String algoritmo, SecretKey llaveSimetrica) throws NoSuchAlgorithmException, InvalidKeyException
	{

		Mac mac = Mac.getInstance(algoritmo);
		mac.init(llaveSimetrica);
		byte[] msg = "15;41 24.2028,2 10.4418".getBytes();

		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}

	public static boolean verificar(byte[] enviado, byte[] recibido) throws Exception
	{
		if (enviado.length != recibido.length) {
			return false;
		}
		for (int i = 0; i < enviado.length; i++) {
			if (enviado[i] != recibido[i]) return false;
		}
		return true;
	}
	
	public static void imprimir (byte[ ] contenido) {
		int i  = 0;
		for(; i < contenido.length - 1; i++) {
			System.out.print(contenido[i] + " ");
		}
		System.out.println(contenido[i] + " ");
	}
}


package Cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.*;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Protocolo {
	private static String[] CADENAS_DE_CONTROL = {"HOLA","ALGORITMOS","OK","ERROR"};
	private static String PADDING = "AES/ECB/PKCS5Padding";

	public static void procesar (String algoritmos,BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException
	{
		pOut.println(CADENAS_DE_CONTROL[0]);
		String fromServer = "";
		//Si no llega del servidor no es null
		if((fromServer = pIn.readLine())!= null && fromServer.equalsIgnoreCase(CADENAS_DE_CONTROL[2]))
		{
			System.out.println("Respuesta del servidor: "+ fromServer);
			pOut.println(algoritmos);
			fromServer = pIn.readLine();
			if((fromServer != null && fromServer.equalsIgnoreCase(CADENAS_DE_CONTROL[2])))
			{
				//llaves asimetricas con RSA
				String[] algoritmos2 = algoritmos.split(":");
				KeyPairGenerator generator = KeyPairGenerator.getInstance(algoritmos2[2]);
				generator.initialize(1024);//inicializa el generador que va a crear llaves del tamaño que se envio como parametro
				KeyPair pareja = generator.generateKeyPair();
				PublicKey llavePublica = pareja.getPublic();
				PrivateKey llavePrivada = pareja.getPrivate();

				//Llave simetrica
				KeyGenerator keyGen = KeyGenerator.getInstance(algoritmos2[1]);
				SecretKey llaveSimetrica = keyGen.generateKey();
				//enviar certificado cliente

				X509Certificate certificadoCliente = generarCertificadoCliente(llavePublica,llavePrivada,algoritmos2[3]);
				byte[] certificadoEnBytes = certificadoCliente.getEncoded();

				String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
				pOut.println(certificadoEnString);

				X509Certificate certificadoServidor = recibirCertificadoServidor(pIn);

				byte[] textoCifradoEnviar = cifrarAsimetrico(certificadoServidor.getPublicKey(),llaveSimetrica);
				if(textoCifradoEnviar!= null) 
				{
					pOut.println(textoCifradoEnviar);
				}
				if((fromServer = pIn.readLine())!= null)
				{
					System.out.println("hola4");
					byte[] textoDescifrado = descifrarAsimetricoConLlavePrivada(fromServer, llavePrivada);
					String textoDC = new String(textoDescifrado);
					String textoC = new String(textoCifradoEnviar);
					if(textoC.equalsIgnoreCase(textoDC))
					{
						pOut.println(CADENAS_DE_CONTROL[2]);
					}
					cifrarSimetrico(llaveSimetrica);
					byte[] digest = hmac(algoritmos2[2], llaveSimetrica);
					if((fromServer = pIn.readLine())!= null && !fromServer.equals(CADENAS_DE_CONTROL[3]))
					{
						//TODO verificar lo que me envia
						byte[] rta = descifrarAsimetricoConLlavePublica(fromServer, certificadoServidor.getPublicKey());
						String aux1 = new String(rta);
						String aux2 = new String(digest);
						if(aux1.equals(aux2))
						{
							System.out.println("termino exitosamente");
						}
					}
				}
			}
			else if((fromServer = pIn.readLine())!= null && fromServer.equalsIgnoreCase(CADENAS_DE_CONTROL[3]))
			{
				//TODO ERROR
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
		//TODO
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);

		long now = System.currentTimeMillis();
		Date startDate = new Date(now);

		X500Name dnName = new X500Name("CN=Cliente");
		BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

		Date endDate = calendar.getTime();

		String numSha = algoritmo.substring(7, algoritmo.length());
		String signatureAlgorithm = "SHA"+numSha+"WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privada);

		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, publica);

		// Extensions --------------------------

		// Basic Constraints
		BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

		// -------------------------------------
		return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
	}
	public static X509Certificate recibirCertificadoServidor(BufferedReader pIn) throws IOException, CertificateException
	{
		//TODO revisar si funciona
		byte[] certificadoEnBytes = DatatypeConverter.parseHexBinary(pIn.readLine());
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		X509Certificate certificado = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificadoEnBytes));
		return certificado;
	}
	public static byte[] cifrarAsimetrico(PublicKey llavePublicaServidor, SecretKey llaveSimetrica)
	{
		try
		{
			Cipher cifrador = Cipher.getInstance(ConSeguridad.ALGORITMO_ASIMETRICO);
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
			System.out.println("aqui");
			Cipher cifrador = Cipher.getInstance(ConSeguridad.ALGORITMO_ASIMETRICO);
			System.out.println("aqui2");
			cifrador.init(Cipher.DECRYPT_MODE, llavePrivadaCliente);
			System.out.println("aqui3");
			textoClaro = cifrador.doFinal(fromServer.getBytes());
			System.out.println("aqui4");
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
			Cipher cifrador = Cipher.getInstance(ConSeguridad.ALGORITMO_ASIMETRICO);
			cifrador.init(Cipher.DECRYPT_MODE, llavePublicaCliente);

			textoClaro = cifrador.doFinal(fromServer.getBytes());
			return textoClaro;
		}
		catch(Exception e)
		{
			System.out.println("Excepcion: "+e.getMessage());
			return null;
		}
	}
	public static byte[] hmac(String algoritmo, SecretKey llaveSimetrica)
	{
		//TODO que se hace con esto?
		//SHA-X
		//"15;41 24.2028,2 10.4418".getBytes();
		String numSha = algoritmo.substring(7, algoritmo.length());

		byte[] shaX = Digest.getDigest("SHA-"+numSha, llaveSimetrica.getEncoded());

		return shaX;
	}
}


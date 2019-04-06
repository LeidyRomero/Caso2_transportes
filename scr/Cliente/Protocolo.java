package Cliente;

import java.io.BufferedReader;
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
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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
	private static String SEPARADOR = ":";

	public static void procesar (String algoritmos,BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException
	{
		pOut.println(CADENAS_DE_CONTROL[0]);
		String fromServer = "";
		//Si no llega del servidor no es null
		if((fromServer = pIn.readLine())!= null && fromServer.equalsIgnoreCase(CADENAS_DE_CONTROL[2]))
		{
			System.out.println("Respuesta del servidor: "+ fromServer);
			pOut.println(algoritmos);

			if((fromServer = pIn.readLine())!= null && fromServer.equalsIgnoreCase(CADENAS_DE_CONTROL[2]))
			{
				//llaves asimetricas
				String[] algoritmos2 = algoritmos.split(":");
				KeyPairGenerator generator = KeyPairGenerator.getInstance(algoritmos2[1]);
				generator.initialize(1024);//inicializa el generador que va a crear llaves del tamaño que se envio como parametro
				KeyPair pareja = generator.generateKeyPair();
				PublicKey llavePublica = pareja.getPublic();
				PrivateKey llavePrivada = pareja.getPrivate();

				//Llave simetrica
				KeyGenerator keyGen = KeyGenerator.getInstance(ConSeguridad.ALGORITMO_ASIMETRICO);
				SecretKey secretKey = keyGen.generateKey();

				//TODO enviar certificado cliente
				X509Certificate certificadoCliente = generarCertificadoCliente(llavePublica,llavePrivada);
				pOut.println(certificadoCliente);

				X509Certificate certificadoServidor = recibirCertificadoServidor();

				byte[] textoCifradoEnviar = cifrar(certificadoServidor.getPublicKey(),secretKey);
				if(textoCifradoEnviar!= null) pOut.println(textoCifradoEnviar);

				if((fromServer = pIn.readLine())!= null)
				{
					descifrar(fromServer, llavePrivada);
					hmac();
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
	public static X509Certificate generarCertificadoCliente(PublicKey publica, PrivateKey privada) throws CertIOException, OperatorCreationException, CertificateException
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

		String signatureAlgorithm = "SHA512WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privada);

		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, publica);

		// Extensions --------------------------

		// Basic Constraints
		BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

		// -------------------------------------

		return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
	}
	public static X509Certificate recibirCertificadoServidor()
	{
		//TODO
		return null;
	}
	public static byte[] cifrar(PublicKey llavePublicaServidor, SecretKey llaveSimetrica)
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
	public static byte[] descifrar(String fromServer, PrivateKey llavePrivadaCliente)
	{
		byte[] textoClaro;

		try
		{
			Cipher cifrador = Cipher.getInstance(ConSeguridad.ALGORITMO_ASIMETRICO);
			cifrador.init(Cipher.DECRYPT_MODE, llavePrivadaCliente);

			textoClaro = cifrador.doFinal(fromServer.getBytes());
			return textoClaro;
		}
		catch(Exception e)
		{
			System.out.println("Excepcion: "+e.getMessage());
			return null;
		}
	}
	public static void hmac()
	{
		//TODO
	}
}


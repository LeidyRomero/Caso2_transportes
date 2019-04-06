package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SinSeguridad {

	public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";

	public static final String HOLA = "HOLA";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String OK = "OK";
	public static final String SEPARADOR = ":";
	public static final String AES = "AES";
	public static final String RSA = "RSA";
	public static final String HMACSHA512 = "HMACSHA512";

	public static void main(String args[]) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException
	{
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		System.out.println("Cliente...");

		try {
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}

		procesar(lector, escritor);

		escritor.close();
		lector.close();
		socket.close();
	}

	public static void procesar(BufferedReader pIn, PrintWriter pOut) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {

		pOut.println(HOLA);

		String fromServer = "";

		if((fromServer = pIn.readLine()) != null && fromServer.equals(OK)) {
			System.out.println("Respuesta servidor: " + fromServer);
			pOut.println(ALGORITMOS+SEPARADOR+AES+SEPARADOR+RSA+SEPARADOR+HMACSHA512);
			System.out.println("Repsuesta cliente: " + ALGORITMOS+SEPARADOR+AES+SEPARADOR+RSA+SEPARADOR+HMACSHA512);
		}

		if((fromServer = pIn.readLine()) != null && fromServer.equals(OK)) {

			System.out.println("Respuesta servidor: " + fromServer);
			//Llaves
			KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
			generator.initialize(1024);
			KeyPair keyPair = generator.generateKeyPair();
			PublicKey llavePublica = keyPair.getPublic();
			PrivateKey llavePrivada = keyPair.getPrivate();

			//Certificado
			X509Certificate certificado = generarCertificado(llavePublica, llavePrivada);
			byte[] certificadoEnBytes = certificado.getEncoded( );
			String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
			pOut.println(certificadoEnString);
		}

		if((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta servidor: " + fromServer);
			byte[] b = new byte[128];
			new Random().nextBytes(b);
			String cadenaBytes = DatatypeConverter.printHexBinary(b);
			pOut.println(cadenaBytes);
			System.out.println("Repsuesta cliente: " + cadenaBytes);
		}

		if((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta servidor: " + fromServer);

			
			pOut.println(OK);
			pOut.println("<Datos>");
			pOut.println("<Datos>");
			System.out.println("Repsuesta cliente: " + OK);
			System.out.println("Repsuesta cliente: " + "<Datos>");
			System.out.println("Repsuesta cliente: " + "<Datos>");
		}

		if((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta servidor: " + fromServer);
			if(!fromServer.equals("ERROR"))
			{
				//TODO Verificar que los datos que llegan
			}
		}


	}

	public static X509Certificate generarCertificado(PublicKey publica, PrivateKey privada) throws OperatorCreationException, CertIOException, CertificateException {
		
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
}

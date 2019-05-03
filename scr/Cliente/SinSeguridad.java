package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
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

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;
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
		
		System.out.println("Cliente: empezando comunicación");
		
		if((fromServer = pIn.readLine()) != null && fromServer.equals(OK)) {
			pOut.println(ALGORITMOS+SEPARADOR+AES+SEPARADOR+RSA+SEPARADOR+HMACSHA512);
			System.out.println("Cliente: " + ALGORITMOS+SEPARADOR+AES+SEPARADOR+RSA+SEPARADOR+HMACSHA512);
		}

		if((fromServer = pIn.readLine()) != null && fromServer.equals(OK)) {
			
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
			
			System.out.println("Cliente: envía certificado");
		}

		if((fromServer = pIn.readLine()) != null) {
			System.out.println("Cliente: recibe cetificado del servidor");
			byte[] b = new byte[128];
			new Random().nextBytes(b);
			String cadenaBytes = DatatypeConverter.printHexBinary(b);
			pOut.println(cadenaBytes);
			System.out.println("Cliente: envía 128 Bytes");
		}
		String datos = "";	
		if((fromServer = pIn.readLine()) != null) {			
			pOut.println(OK);
			datos = "15;41 24.2028,2 10.4418";						
			pOut.println(datos);
			pOut.println(datos);
			System.out.println("Cliente: " + OK);
			System.out.println("Cliente: " + datos);
			System.out.println("Cliente: " + datos);
		}

		if((fromServer = pIn.readLine()) != null) {
			if(!fromServer.equals("ERROR") && fromServer.equals(datos))
			{
				System.out.println("Cliente: verificación exitosa de los datos");
				System.out.println("Cliente: termina exitosamente");
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
	
	public double getSystemCpuLoad() throws MalformedObjectNameException, NullPointerException, InstanceNotFoundException, ReflectionException
	{
		MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		ObjectName name = ObjectName.getInstance("java.lang:type=OperatingSystem");
		AttributeList list = mbs.getAttributes(name,new String[] {"SystemCpuLoad"});
		
		if(list.isEmpty()) return Double.NaN;
		
		Attribute att = (Attribute) list.get(0);
		Double value = (Double) att.getValue();
		
		if(value == -1.0 ) return Double.NaN;
		
		return ((int) (value*1000)/10.0);
	}
}

package ServidorConSeguridadCambios;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;


public class C {
	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	private static X509Certificate certSer; /* acceso default */
	private static KeyPair keyPairServidor; /* acceso default */
	//TODO Pool de threads
	private static ExecutorService pool;
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		System.out.println(MAESTRO + "Establezca puerto de conexion:");
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		int ip = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		// Adiciona la libreria como un proveedor de seguridad.
		// Necesario para crear llaves.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		
		// Crea el socket que escucha en el puerto seleccionado.
		ss = new ServerSocket(ip);
		System.out.println(MAESTRO + "Socket creado.");


		int idThread = 0;
		//TODO Se pide el número de threads por consola
		System.out.println(MAESTRO + "Establezca número de threads:");
		int numeroThreads = Integer.parseInt(br.readLine());
		//TODO Se inicializa el pool con el número de threads dados
		pool = Executors.newFixedThreadPool(numeroThreads);
		System.out.println(MAESTRO + "Pool creado.");
		
		//TODO Se pide el número de clientes esperado por consola
		System.out.println(MAESTRO + "Establezca número de clientes:");
		int numeroClientes = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Número de clientes creado.");

		keyPairServidor = S.grsa();
		certSer = S.gc(keyPairServidor);
		D.initCertificate(certSer, keyPairServidor);
		
		//TODO se crean los archivos donde se van a escribir los datos de los monitores
		PrintWriter escritorTiempo = new PrintWriter(new FileWriter("./data/tiemposConSeguridad.csv", true));
		PrintWriter escritorCPU = new PrintWriter(new FileWriter("./data/cpuConSeguridad.csv", true));
		PrintWriter escritorTransacciones = new PrintWriter(new FileWriter("./data/transaccionesExitosas.csv", true));
		
		escritorTiempo.println("--------------------------");
		escritorTiempo.println("Threads: " + numeroThreads + " - Clientes: " + numeroClientes);
		
		escritorCPU.println("--------------------------");
		escritorCPU.println("Threads: " + numeroThreads + " - Clientes: " + numeroClientes);
		
		escritorTransacciones.println("--------------------------");
		escritorTransacciones.println("Threads: " + numeroThreads + " - Clientes: " + numeroClientes);
		
		escritorTiempo.close();
		escritorTransacciones.close();
		escritorCPU.close();
		
		while (true) {
			try { 
				Socket sc = ss.accept();
				System.out.println(MAESTRO + "Cliente " + idThread + " aceptado.");
				D d = new D(sc,idThread, numeroClientes);
				idThread++;
				//TODO Asigna un thread del pool por conexión
				pool.execute(d);
			} catch (IOException e) {
				System.out.println(MAESTRO + "Error creando el socket cliente.");
				//TODO Detiene la ejecución del thread
				shutdownAndAwaitTermination(pool);
				e.printStackTrace();
				
				//TODO Cierra los escritores de los archivos de los monitores
				escritorTiempo.close();
				escritorCPU.close();
				escritorTransacciones.close();
			}
		}
	}
	public static void shutdownAndAwaitTermination(ExecutorService pool) {
		pool.shutdown(); // Disable new tasks from being submitted
		try {
			// Wait a while for existing tasks to terminate
			if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
				pool.shutdownNow(); // Cancel currently executing tasks
				// Wait a while for tasks to respond to being cancelled
				if (!pool.awaitTermination(60, TimeUnit.SECONDS))
					System.err.println("Pool did not terminate");
			}
		} catch (InterruptedException ie) {
			// (Re-)Cancel if current thread also interrupted
			pool.shutdownNow();
			// Preserve interrupt status
			Thread.currentThread().interrupt();
		}
	}
}
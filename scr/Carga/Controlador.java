package Carga;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;
/**
 * 3 Monitores: tiempo parcial de transaccion, uso de CPU, numero de transacciones perdidas.
 * @author Maria Ocapo y Leidy Romero
 */
public class Controlador {
	/**
	 * Objeto con el que se controla la generacion de todas las transacciones a generar.
	 */
	private LoadGenerator generador;
	/**
	 * Constructor que genera la carga
	 * Se generan 100 transacciones de comnicacion con el servidor, cada una con una separacion de 1 segundo
	 */
	public Controlador()
	{
		//Tarea que se  a a ejecutar concurrentemente
		Task work = createTask();
		//TODO primera prueba: 400, 200, 80
		int numeroDeTareas = 400;
		//Si se quiere que todas las transacciones se ejecuten en simultaneo el siguiente valor debe ser 0
		//TODO Primera prueba: 20, 40, 100
		int tiempoEntreTareas = 20;
		generador = new LoadGenerator("Nombre", numeroDeTareas , work, tiempoEntreTareas);
		//metodo que inicia la produccion de carga
		generador.generate();
	}
	/**
	 * Metodo que se encarga de instanciar la tarea a ejecutar concurrentemente
	 * @return
	 */
	private Task createTask()
	{
		//TODO Se cambia entre las tareas del servidor con seguridad y las del servidor sin seguridad
		return new TareaClienteServidorConSeguridad();
	}
	public static void main(String[] args)
	{
		Controlador controlador = new Controlador();
	}
}

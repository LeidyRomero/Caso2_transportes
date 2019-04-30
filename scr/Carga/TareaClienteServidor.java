package Carga;

import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.Client;
/**
 * 
 * @author Maria Ocampo y Leidy Romero
 *
 */
public class TareaClienteServidor extends Task {
	private Client Cliente;
	public TareaClienteServidor(Client pCliente)
	{
		Cliente = pCliente;
	}
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
	}

	public void success() {
		System.out.println(Task.OK_MESSAGE);
	}
	/**
	 * Se crean diferentes clientes qe envian un mensaje a un servidor y esperan su respuesta. 
	 * Si se quiere que un mismo cliente envie varios mensajes se debe modificar el constructor 
	 * para que reciba como parametro el cliente y lo asigne a un atributo en la clase
	 */
	public void execute() {
		Client cliente = new Client();
		cliente.sendMessageToServer("Cliente...");
		cliente.waitForMessageFromServer();
		//TODO revisar * envios desde "Cliente"
	}

}

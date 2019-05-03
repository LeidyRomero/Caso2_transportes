package Carga;

import java.lang.management.ManagementFactory;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;

public class CPU {
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

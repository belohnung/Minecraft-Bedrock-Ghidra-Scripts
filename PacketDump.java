import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

public class PacketDump extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Function currentFunction = this.getFunctionAt(this.currentAddress);
		
		boolean onlyThis = true;
		
		if(currentFunction != null && currentFunction.getName().equalsIgnoreCase("_read")) {
			onlyThis = this.askYesNo("Dump Options", "Do you want to dump the current Packet? (" + currentFunction.getParentNamespace().getName() + ")");
			if(onlyThis) {
				this.processFunction(currentFunction);
				return;
			}
		}
		boolean allPackets = this.askYesNo("Dump Options", "Do you want to dump all Packets?");
		
		if(allPackets) {
			for (Iterator<GhidraClass> iterator = this.getState().getCurrentProgram().getSymbolTable()
					.getClassNamespaces(); iterator.hasNext();) {
				GhidraClass clazz = iterator.next();

				if (clazz.getName().endsWith("Packet")) {
					for (AddressRange addressRange : clazz.getBody().getAddressRanges()) {
						Function func = this.getFunctionAt(addressRange.getMinAddress());
						if (func != null) {
							this.processFunction(func);
						}
					}
				}
			}
		}else {
			Address address = this.askAddress("Select a Packet", "Select the _read function of the Packet you want to Dump");
			
			
			while (!this.isValidReadAddress(address)) {
				address = this.askAddress("Select a Packet", "Select the _read function of the Packet you want to Dump");
			}
			
			this.processFunction(this.getFunctionAt(address));
		}
		

	}
	
	public boolean isValidReadAddress(Address address) {
		Function currentFunction = this.getFunctionAt(address);
		
		return currentFunction != null && currentFunction.getName().equalsIgnoreCase("_read");
	}
	
	
	public void processFunction(Function readFunction) {
		AtomicInteger byte1 = new AtomicInteger();
		Address address = readFunction.getEntryPoint();
		if (readFunction != null) {
			//println("Current Function: " + readFunction.getName(true) +" (0x" + address.toString() + ")");
			if (readFunction.getName().contains("read")) {
				readFunction.getParentNamespace().getBody().getAddressRanges().forEach(range -> {

					for (Address addr : range) {
						Function fnc = this.getFunctionAt(addr);
						if (fnc != null) {
							if (fnc.getName().toLowerCase().contains("getid".toLowerCase())) {
								Instruction inst = this.getInstructionBefore(fnc.getBody().getMaxAddress());
								try {
									byte packetId = inst.getByte(1);
									byte1.set(packetId);
								} catch (MemoryAccessException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}

						}
					}
				});

				println(String.format("Packet: %s (0x%02X)", readFunction.getParentNamespace().getName(), (byte) byte1.get()));

				readFunction.getCalledFunctions(monitor).forEach(function -> {
					if (function.getParentNamespace().getName().toLowerCase().contains("binarystream"))
						println(function.getName(true));
				});
			}
		} else {
			println("Function is null");
		}
	}

}

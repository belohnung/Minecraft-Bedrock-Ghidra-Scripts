import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableFilter;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class PacketVariableNamer extends GhidraScript {

	boolean overwriteUserDefined = false;

	boolean processCurrentFunction = false;

	boolean onlyPackets = false;

	@Override
	protected void run() throws Exception {
		this.overwriteUserDefined = this.askYesNo("Overwrite User Defined Variables",
				"Should the script overwrite user defined variable names?");
		this.processCurrentFunction = this.askYesNo("Process Current Function",
				"Should the script only operate on the current function?");
		if (!this.processCurrentFunction) {
			this.onlyPackets = this.askYesNo("Process only Packets",
					"Should the script only operate on Packet Classes?");
		} else {
			this.onlyPackets = false;
		}

		if (!processCurrentFunction) {
			for (Iterator<GhidraClass> iterator = this.getState().getCurrentProgram().getSymbolTable()
					.getClassNamespaces(); iterator.hasNext();) {
				GhidraClass clazz = iterator.next();

				if (!this.onlyPackets || clazz.getName().endsWith("Packet")) {
					for (AddressRange addressRange : clazz.getBody().getAddressRanges()) {
						// println(addressRange.getMinAddress().toString() + " - "
						// + addressRange.getMaxAddress().toString());
						Function func = this.getFunctionAt(addressRange.getMinAddress());
						if (func != null) {
							Set<String> variableNames = new HashSet<String>();
							this.processFunction(func, variableNames);
						}
					}
					// println(clazz.getName() + " Isglobal: " + clazz.getSymbol().isGlobal());
				}
			}
		} else {
			Set<String> variableNames = new HashSet<String>();
			Function func = this.getFunctionAt(this.currentAddress);
			this.processFunction(func, variableNames);
		}
	}

	public void processFunction(Function func, Set<String> names) throws DuplicateNameException, InvalidInputException {
		for (Variable var : func.getVariables(VariableFilter.PARAMETER_FILTER)) {
			// println(var.getName() + ":" + var.getSource());
			if (!var.getName().equalsIgnoreCase("this") && this.checkSource(var.getSource())) {
				String newName = this.getCamelCaseName(var.getDataType().getDisplayName()).replace("*", "").trim();
				String outNewName = newName;
				int counter = 1;
				while (!names.add(outNewName)) {
					outNewName = newName + "_" + counter;
					counter++;
				}
				println(var.getName() + "-> " + outNewName);
				 var.setName(outNewName,
				 SourceType.USER_DEFINED);
			}
		}
	}

	public boolean checkSource(SourceType input) {
		return this.overwriteUserDefined || input.equals(SourceType.USER_DEFINED);
	}

	public String getCamelCaseName(String input) {
		String output = Character.toLowerCase(input.charAt(0)) + input.substring(1);

		if (output.contains("<")) {
			output = output.split("<")[0];
		}
		output = "param_" + output;
		return output;
	}

}

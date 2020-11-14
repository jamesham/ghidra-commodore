/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package commodoreloader;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import generic.jar.ResourceFile;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramAddressFactory;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;
import ghidra.xml.XmlTreeNode;

/**
 * Loads Commodore 64 cartridge files
 */
public class CommodoreCartridgeLoader extends AbstractLibrarySupportLoader {
	
	private String loaderName = "Commodore Cartridge Loader";
	public final static String CART_FMT_NAME = "Commodore Cartridge";

	@Override
	public String getName() {
		return loaderName;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		try {
			@SuppressWarnings("unused")
			CommodoreCartridgeHeader cart = CommodoreCartridgeHeader.createCommodoreCartridgeHeader(RethrowContinuesFactory.INSTANCE, provider);
		
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"),true));
		} catch (CommodoreException e) {
			// pass // not a Commodore Cart
			Msg.error(this,"Error parsing C64 cart: ", e);
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		try {
			
			monitor.setMessage(loaderName + ": Starting loading");
			
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			CommodoreCartridgeHeader cart = CommodoreCartridgeHeader.createCommodoreCartridgeHeader(factory, provider);
			cart.parse();
			
			addCartridgeProperties(program, cart, monitor);
			
			addSystemAddressSegments(program, log, monitor);
			addCartridgeChips(program, cart, log, monitor);
			
			monitor.setMessage(loaderName + ": Completed loading");
			
		} catch (CommodoreException e) {
			e.printStackTrace();
			throw new IOException(e.getMessage());
		}
	}
	
	private void addCartridgeProperties(Program program, CommodoreCartridgeHeader cart, TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString("Cartridge Type", cart.getCart_hardware_type_string() + " (" + cart.getCart_hardware_type() + ")");
		props.setString("Cartridge Signature", cart.getCart_magic_str());
		props.setInt("Cartridge Header Length", cart.getCart_header_len());
		props.setString("Cartridge Format Version", cart.getCart_version_str());
		props.setInt("Cartridge Line EXROM", cart.getCart_exrom_status());
		props.setInt("Cartridge Line GAME", cart.getCart_game_status());
		props.setString("Cartridge Name", cart.getCart_name());
		props.setInt("Cartridge Chip Count", cart.getCart_chip_count());
		monitor.checkCanceled();
	}
	
	private void addSystemAddressSegments(Program program, MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		if (!(program.getAddressFactory() instanceof ProgramAddressFactory)) {
			throw new IOException("Unexpected error: AddressFactory is not a ProgramAddressFactory");
		}

		ProgramAddressFactory af = (ProgramAddressFactory) program.getAddressFactory();
		AddressSpace as = af.getDefaultAddressSpace();

		Address ramBaseAfterStack = as.getAddressInThisSpaceOnly(0x200);
		Address ioAddress = as.getAddress(0xd000);
		MemoryBlockUtils.createUninitializedBlock(program, false, "RAM", ramBaseAfterStack, 0x10000-0x200, "C64 System RAM", "C64 Hardware", true, true, true, log);
		MemoryBlock ioMemoryBlock = MemoryBlockUtils.createUninitializedBlock(program, true, "I_O", ioAddress, 0x1000, "C64 I/O Registers", "C64 Hardware", true, true, false, log);
		ioMemoryBlock.setVolatile(true);

		log.appendMsg(String.format("Name: %s\nPointerSize: %d\nSize: %d\nMinAddr: %s\nMaxAddr: %s\nType: %d\n", as.getName(), as.getPointerSize(), as.getSize(), as.getMinAddress(), as.getMaxAddress(), as.getType()));

		List<ResourceFile> allRomspecFiles = Application.findFilesByExtensionInMyModule(".romspec");
		for (ResourceFile romspecFile : allRomspecFiles) {
			overlaySystemRom(romspecFile, program, log, monitor);
		}
		
	}
	
	private void overlaySystemRom(ResourceFile romspecFile, Program program, MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		
		MyErrorHandler errHandler = new MyErrorHandler(log);
		
		try {
			XmlPullParser xmlParser = XmlPullParserFactory.create(romspecFile,errHandler,false);
			XmlTreeNode romTree = new XmlTreeNode(xmlParser);
			XmlElement ele = romTree.getStartElement();
			String name = ele.getName();
			String type = ele.getAttribute("system_type");
			String source = ele.getAttribute("source");
			log.appendMsg(String.format("Root: %s (%s)", name, type));
			Iterator<XmlTreeNode> it = romTree.getChildren("rom");
			while (it.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				XmlTreeNode node = it.next();
				addSystemRom(node, source, program, log, monitor);
				//XmlElement childElement = node.getStartElement(); 
				
			}
		} catch (SAXException e) {
			throw new IOException(e);
		}
	}
	
	private void addSystemRom(XmlTreeNode romNode, String source, Program program, MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		if (monitor.isCancelled()) {
			throw new CancelledException();
		}
		XmlElement romElement = romNode.getStartElement();
		if (!romElement.getName().equals("rom")) {
			throw new IOException("Missing XML rom element");
		}
		String romName = romElement.getAttribute("name");
		String romPath = romElement.getAttribute("romFile");
		String romDesc = romElement.getAttribute("description");
		String romSource = romElement.getAttribute("source");
		int romStart = XmlUtilities.parseInt(romElement.getAttribute("addressStart"));
		int romLength = XmlUtilities.parseInt(romElement.getAttribute("length"));
		log.appendMsg(String.format("ROM: %s (%s) at %x (%x)", romName, romPath, romStart, romLength));
		
		ProgramAddressFactory af = (ProgramAddressFactory) program.getAddressFactory();
		AddressSpace as = af.getDefaultAddressSpace();
		
		Address romStartAddress = as.getAddress(romStart);
		MemoryBlock romMemoryBlock = null;
		
		try {
			ResourceFile romBin = Application.getModuleDataFile(romPath);
			romMemoryBlock = MemoryBlockUtils.createInitializedBlock(program, true, romName, romStartAddress, romBin.getInputStream(), romLength, romDesc, romSource, true, false, true, log, monitor);
		} catch (AddressOverflowException e) {
			log.appendMsg(e.getMessage());
			throw new IOException("Bad address in ROMSPEC: " + e.getMessage());
		} catch (FileNotFoundException e) {
			log.appendMsg(e.getMessage());
			romMemoryBlock = MemoryBlockUtils.createInitializedBlock(program, true, romName, romStartAddress, romLength, romDesc + " (file not found)", romSource, true, false, true, log);
		}
		
		romMemoryBlock.setSourceName(romSource);
		
		AddressSpace romAddressSpace = af.getAddressSpace(romName);
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace romNamespace = symbolTable.getNamespace(romAddressSpace.getAddress(romStart));
		
		Iterator<XmlTreeNode> it = romNode.getChildren("symbol");
		while (it.hasNext()) {
			XmlElement symbol = it.next().getStartElement();
			if (!(symbol.getName().equals("symbol"))) {
				log.appendMsg("Found non-symbol element: " + symbol.getName());
				continue;
			}
			String symbolName = symbol.getAttribute("name");
			int symbolAddr = XmlUtilities.parseInt(symbol.getAttribute("address"));
			Address symbolAddress = romAddressSpace.getAddress(symbolAddr);
			try {
				symbolTable.createLabel(symbolAddress, symbolName, romNamespace, SourceType.IMPORTED);
				symbolTable.addExternalEntryPoint(symbolAddress);
			} catch (InvalidInputException e) {
				log.appendMsg(String.format("Error creating symbol \"%s\": %s", symbolName, e.getMessage()));
			}
		}
	}
	
	private void addCartridgeChips(Program program, CommodoreCartridgeHeader cart, MessageLog log, TaskMonitor monitor) {
		
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		return null;
	}
	
	class MyErrorHandler implements ErrorHandler {
		private MessageLog log;
		
		MyErrorHandler(MessageLog log) {
			this.log = log;
		}
		@Override
		public void error(SAXParseException exception) throws SAXException {
			log.appendMsg(exception.getMessage());
		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			log.appendMsg(exception.getMessage());
		}
		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			log.appendMsg(exception.getMessage());
		}
	}
}

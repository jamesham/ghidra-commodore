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

import commodore.CommodoreUtils;
import commodore.CommodoreXMLUtils;
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
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
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
	
	public final static String PROPERTY_CART_TYPE = "Cartridge Type";
	public final static String PROPERTY_CART_SIGNATURE = "Cartridge Signature";
	public final static String PROPERTY_CART_HEADER_LEN = "Cartridge Header Length";
	public final static String PROPERTY_CART_FORMAT_VER = "Cartridge Format Version";
	public final static String PROPERTY_CART_EXROM_STATUS = "Cartridge Line EXROM";
	public final static String PROPERTY_CART_GAME_STATUS = "Cartridge Line GAME";
	public final static String PROPERTY_CART_NAME = "Cartridge Name";
	public final static String PROPERTY_CART_CHIP_COUNT = "Cartridge Chip Count";
	
	public final static String DTM_PATH = "/Commodore";

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
		
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"),true)); //$NON-NLS-1$ //$NON-NLS-2$
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
			cart.parse(program, monitor, log);
			
			addCartridgeProperties(program, cart, monitor);
			
			addSystemAddressSegments(cart, program, log, monitor);
			addCartridgeChips(program, cart, log, monitor);
			
			addHeaders(program, cart, log, monitor);
			
			monitor.setMessage(loaderName + ": Completed loading");
			
		} catch (CommodoreException e) {
			e.printStackTrace();
			throw new IOException(e.getMessage());
		}
	}
	
	private void addHeaders(Program program, CommodoreCartridgeHeader cart, MessageLog log, TaskMonitor monitor) throws CancelledException {
		
		monitor.checkCanceled();
				
		Address headerAddr = AddressSpace.OTHER_SPACE.getAddress(0);
		Data lastBlock;
		try {
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, false, "Cart Header", headerAddr, cart.getCart_header_filebytes(), 0, cart.getCart_header_len(), cart.getCart_name(), cart.getCart_source(), true, false, false, log);
			lastBlock = DataUtilities.createData(program, headerBlock.getStart(), cart.toDataType(), cart.getCart_header_len(), false, ClearDataMode.CHECK_FOR_SPACE);
			
			for (CommodoreChipHeader chip : cart.getChips()) {			
				Address nextAddr = AddressSpace.OTHER_SPACE.getAddress(lastBlock.getMaxAddress().getOffset() + 1);
				headerBlock = MemoryBlockUtils.createInitializedBlock(program, false, chip.getChip_name()+"_HEADER", nextAddr, chip.getChip_header_bytes(), 0, chip.getChip_header_length(), chip.getChip_name()+"_HEADER", chip.get_chip_source(), true, false, false, log);
				lastBlock = DataUtilities.createData(program, headerBlock.getStart(), chip.toDataType(), chip.getChip_header_length(), false, ClearDataMode.CHECK_FOR_SPACE);
			}
			
		} catch (AddressOverflowException | CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(String.format("Error creating header: %s", e.getMessage()));
		}
		
		

	}
	
	private void addCartridgeProperties(Program program, CommodoreCartridgeHeader cart, TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString(PROPERTY_CART_TYPE, cart.getCart_hardware_type_string() + " (" + cart.getCart_hardware_type() + ")");
		props.setString(PROPERTY_CART_SIGNATURE, cart.getCart_magic_str());
		props.setInt(PROPERTY_CART_HEADER_LEN, cart.getCart_header_len());
		props.setString(PROPERTY_CART_FORMAT_VER, cart.getCart_version_str());
		props.setInt(PROPERTY_CART_EXROM_STATUS, cart.getCart_exrom_status());
		props.setInt(PROPERTY_CART_GAME_STATUS, cart.getCart_game_status());
		props.setString(PROPERTY_CART_NAME, cart.getCart_name());
		props.setInt(PROPERTY_CART_CHIP_COUNT, cart.getCart_chip_count());
		monitor.checkCanceled();
	}
	
	private void addSystemAddressSegments(CommodoreCartridgeHeader cart, Program program, MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		if (!(program.getAddressFactory() instanceof ProgramAddressFactory)) {
			throw new IOException("Unexpected error: AddressFactory is not a ProgramAddressFactory");
		}

		ProgramAddressFactory af = (ProgramAddressFactory) program.getAddressFactory();
		AddressSpace as = af.getDefaultAddressSpace();

		long ramBase = 0x200; // Ghidra automatically creates the zero page and stack page for the 6502
		long basicRam = 0x8000; // location of BASIC RAM (mapped as overlay)
		long basicRamSize = 0x2000;
		long bankedRam = 0xa000;
		long bankedRamSize = 0x1000;
		long machineRam = 0xc000;
		long machineRamSize = 0x1000;
		long ioRam = 0xd000;
		long ioRamSize = 0x1000;
		long highRam = 0xe000;
		long highRamSize = 0x2000;
		Address ramBaseAfterStack = as.getAddressInThisSpaceOnly(ramBase);
		Address ioAddress = as.getAddress(0xd000);
		long ramSize = 0x8000 - ramBase; 
		if (cart.isUltimax()) {
			ramSize = 0x1000 - ramBase; // In Ultimax mode, the system maps out all but the bottom 4k of RAM; regardless of CPU control lines, system only maps bottom 4k of RAM, I/O, and cart ROMs
			log.appendMsg("INFO: Cart is set to Ultimax mode! Only the low 4k of RAM is available.");
		}
		MemoryBlockUtils.createUninitializedBlock(program, false, "RAM", ramBaseAfterStack, ramSize, "C64 System RAM", "C64 Hardware", true, true, true, log);
		// the I/O space is the only space at 0xd000 in Ultimax mode, so do not create as overlay if isUltimax
		MemoryBlock ioMemoryBlock = MemoryBlockUtils.createUninitializedBlock(program, !cart.isUltimax(), "I_O", ioAddress, 0x1000, "C64 I/O Registers", "C64 Hardware", true, true, false, log);
		ioMemoryBlock.setVolatile(true);
		
		// these RAM banks are mapped out if cart is in Ultimax mode
		if (!cart.isUltimax()) {
			// BASIC RAM is overlay unless the cart won't actually map in (no idea if such a cart file exists, probably not)
			Address basicRamBase = as.getAddress(basicRam);
			MemoryBlockUtils.createUninitializedBlock(program, cart.willMap(), "RAM_8000", basicRamBase, basicRamSize, "C64 System RAM", "C64 Hardware", true, true, true, log);
			
			// Banked RAM at 0xa000 is usually masked by BASIC ROM or Cart ROM
			Address bankedRamBase = as.getAddress(bankedRam);
			MemoryBlockUtils.createUninitializedBlock(program, true, "RAM_A000", bankedRamBase, bankedRamSize, "C64 System RAM", "C64 Hardware", true, true, true, log);
			
			// Nothing else banks at 0xc000, but this memory is not mapped in for an Ultimax cart
			Address machineRamBase = as.getAddress(machineRam);
			MemoryBlockUtils.createUninitializedBlock(program, false, "RAM_C000", machineRamBase, machineRamSize, "C64 System RAM", "C64 Hardware", true, true, true, log);
			
			// to keep things simple, the default here is the CHAR ROM, RAM is overlay
			Address ioRamBase = as.getAddress(ioRam);
			MemoryBlockUtils.createUninitializedBlock(program, true, "RAM_D000", ioRamBase, ioRamSize, "C64 System RAM", "C64 Hardware", true, true, true, log);
			
			// this is usually Kernal ROM but can be banked out for RAM (but will not be present in Ultimax mode)
			Address highRamBase = as.getAddress(highRam);
			MemoryBlockUtils.createUninitializedBlock(program, true, "RAM_E000", highRamBase, highRamSize, "C64 System RAM", "C64 Hardware", true, true, true, log);
			
		}

		//log.appendMsg(String.format("Name: %s\nPointerSize: %d\nSize: %d\nMinAddr: %s\nMaxAddr: %s\nType: %d\n", as.getName(), as.getPointerSize(), as.getSize(), as.getMinAddress(), as.getMaxAddress(), as.getType()));

		List<ResourceFile> allRomspecFiles = Application.findFilesByExtensionInMyModule(CommodoreXMLUtils.EXT_ROMSPEC);
		for (ResourceFile romspecFile : allRomspecFiles) {
			overlaySystemRom(romspecFile, cart, program, log, monitor);
		}
		
	}
	
	private void overlaySystemRom(ResourceFile romspecFile, CommodoreCartridgeHeader cart, Program program, MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		
		MyErrorHandler errHandler = new MyErrorHandler(log);
		
		try {
			XmlPullParser xmlParser = XmlPullParserFactory.create(romspecFile,errHandler,false);
			XmlTreeNode romTree = new XmlTreeNode(xmlParser);
			XmlElement ele = romTree.getStartElement();
			String source = ele.getAttribute(CommodoreXMLUtils.ATTR_SOURCE);
			//log.appendMsg(String.format("Root: %s (%s)", name, type));
			Iterator<XmlTreeNode> it = romTree.getChildren(CommodoreXMLUtils.TAG_ROM);
			while (it.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				XmlTreeNode node = it.next();
				addSystemRom(node, source, cart, program, log, monitor);
				//XmlElement childElement = node.getStartElement(); 
				
			}
		} catch (SAXException e) {
			throw new IOException(e);
		}
	}
	
	private void addSystemRom(XmlTreeNode romNode, String source, CommodoreCartridgeHeader cart, Program program, MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		if (monitor.isCancelled()) {
			throw new CancelledException();
		}
		XmlElement romElement = romNode.getStartElement();
		if (!romElement.getName().equals(CommodoreXMLUtils.TAG_ROM)) {
			throw new IOException("Missing XML rom element");
		}
		
		String romName = romElement.getAttribute(CommodoreXMLUtils.ATTR_NAME);
		String romPath = romElement.getAttribute(CommodoreXMLUtils.ATTR_ROM_FILE);
		String romDesc = romElement.getAttribute(CommodoreXMLUtils.ATTR_DESC);
		String romSource = romElement.getAttribute(CommodoreXMLUtils.ATTR_SOURCE);
		long romStart = XmlUtilities.parseInt(romElement.getAttribute(CommodoreXMLUtils.ATTR_ADDR_START));
		long romLength = XmlUtilities.parseInt(romElement.getAttribute(CommodoreXMLUtils.ATTR_LENGTH));
		
		if (!romCanMap(romNode, cart, log, monitor)) {
			log.appendMsg(String.format("Omitting ROM: %s (cannot map in this cartridge mode)", romName));
			return;
		}
		
		log.appendMsg(String.format("ROM: %s (%s) at 0x%04x (0x%04x)", romName, romPath, romStart, romLength));
		
		ProgramAddressFactory af = (ProgramAddressFactory) program.getAddressFactory();
		AddressSpace as = af.getDefaultAddressSpace();
		
		Address romStartAddress = as.getAddress(romStart);
		MemoryBlock romMemoryBlock = null;
		
		try {
			ResourceFile romBin = Application.getModuleDataFile(romPath);
			// is overlay
			//romMemoryBlock = MemoryBlockUtils.createInitializedBlock(program, true, romName, romStartAddress, romBin.getInputStream(), romLength, romDesc, romSource, true, false, true, log, monitor);
			// not overlay
			romMemoryBlock = MemoryBlockUtils.createInitializedBlock(program, false, romName, romStartAddress, romBin.getInputStream(), romLength, romDesc, romSource, true, false, true, log, monitor);
		} catch (AddressOverflowException e) {
			log.appendMsg(e.getMessage());
			throw new IOException("Bad address in ROMSPEC: " + e.getMessage());
		} catch (FileNotFoundException e) {
			log.appendMsg(e.getMessage());
			// is overlay
			// romMemoryBlock = MemoryBlockUtils.createInitializedBlock(program, true, romName, romStartAddress, romLength, romDesc + " (file not found)", romSource, true, false, true, log);
			// not overlay
			romMemoryBlock = MemoryBlockUtils.createInitializedBlock(program, false, romName, romStartAddress, romLength, romDesc + " (file not found)", romSource, true, false, true, log);
		}
		
		romMemoryBlock.setSourceName(romSource);
		
		AddressSpace romAddressSpace = af.getAddressSpace(romName);
		if (romAddressSpace == null) {
			romAddressSpace = af.getDefaultAddressSpace();
		}
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace romNamespace = symbolTable.getNamespace(romAddressSpace.getAddress(romStart));
		
		Iterator<XmlTreeNode> it = romNode.getChildren(CommodoreXMLUtils.TAG_SYMBOL);
		while (it.hasNext()) {
			XmlElement symbol = it.next().getStartElement();
			if (!(symbol.getName().equals(CommodoreXMLUtils.TAG_SYMBOL))) {
				log.appendMsg("Found non-symbol element: " + symbol.getName());
				continue;
			}
			String symbolName = symbol.getAttribute(CommodoreXMLUtils.ATTR_NAME);
			long symbolAddr = XmlUtilities.parseInt(symbol.getAttribute(CommodoreXMLUtils.ATTR_ADDRESS));
			String symbolDesc = symbol.getAttribute(CommodoreXMLUtils.ATTR_DESC);
			String symbolType = symbol.getAttribute(CommodoreXMLUtils.ATTR_TYPE);
			Address symbolAddress = romAddressSpace.getAddress(symbolAddr);
			try {
				if (symbolDesc != null) {
					// add description as comment
					program.getListing().setComment(symbolAddress, CodeUnit.PRE_COMMENT, symbolDesc);
				}
				
				if (symbolType.equals(CommodoreXMLUtils.SYMBOL_TYPE_ENTRY)) {
					symbolTable.createLabel(symbolAddress, symbolName, romNamespace, SourceType.IMPORTED);
					symbolTable.addExternalEntryPoint(symbolAddress);
				} else if (symbolType.equals(CommodoreXMLUtils.SYMBOL_TYPE_CODE_POINTER)) {
					// set data type to pointer, try to make destination of pointer into entry point
					CommodoreUtils.createVectorAddress(symbolName, symbolAddress, romNamespace, symbolTable, program, log);
				} else if (symbolType.equals(CommodoreXMLUtils.SYMBOL_TYPE_JUMP_VECTOR)) {
					CommodoreUtils.createJumpVector(symbolName, symbolAddress, romNamespace, symbolTable, program, log);
				} else {
					symbolTable.createLabel(symbolAddress, symbolName, romNamespace, SourceType.IMPORTED);
				}
				
			} catch (InvalidInputException e) {
				log.appendMsg(String.format("Error creating symbol \"%s\": %s", symbolName, e.getMessage()));
			}
		}
	}
	
	private boolean romCanMap(XmlTreeNode romNode, CommodoreCartridgeHeader cart, MessageLog log, TaskMonitor monitor) throws CancelledException {
		
		int cartGameStatus = cart.getCart_game_status();
		int cartExromStatus = cart.getCart_exrom_status();
		
		Iterator<XmlTreeNode> it = romNode.getChildren(CommodoreXMLUtils.TAG_INVAlID_MAP);
		while (it.hasNext()) {
			monitor.checkCanceled();
			
			XmlElement badMap = it.next().getStartElement();
			int romBadGame = -1; int romBadExrom = -1;
			try {
				romBadGame = XmlUtilities.parseInt(badMap.getAttribute(CommodoreXMLUtils.ATTR_GAME));
			} catch (NumberFormatException | NullPointerException e) {
				// pass
			}
			try {
				romBadExrom = XmlUtilities.parseInt(badMap.getAttribute(CommodoreXMLUtils.ATTR_EXROM));
			} catch (NumberFormatException | NullPointerException e) {
				// pass
			}
			if (romBadGame == cartGameStatus || romBadGame == -1) {
				if (romBadExrom == cartExromStatus || romBadExrom == -1) {
					//log.appendMsg(String.format("ROM does not like %d/%d (status is %d/%d)", romBadGame,romBadExrom, gameStatus, exromStatus));
					return false;
				}
			}
		}
		
		return true;
	}
	
	private void addCartridgeChips(Program program, CommodoreCartridgeHeader cart, MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (monitor.isCancelled()) {
			throw new CancelledException();
		}
		ProgramAddressFactory af = (ProgramAddressFactory) program.getAddressFactory();
		AddressSpace as = af.getDefaultAddressSpace();
		SymbolTable symbolTable = program.getSymbolTable();
		
		
		
		CommodoreChipHeader[] chips = cart.getChips();
		for (CommodoreChipHeader chip : chips) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			
			long chipStart = chip.getChip_load_addr();
			String chipName = chip.getChip_name();
			String chipComment = String.format("Cart %s Chip %s", cart.getCart_name(), chipName);
			Address chipStartAddress = as.getAddress(chipStart);
			boolean r = chip.isReadable();
			boolean w = chip.isWritable();
			boolean x = chip.isExecutable();
			FileBytes chipBytes = chip.getChip_filebytes();
			long chipSize = chip.getChip_image_size();
			String chipSource = chip.get_chip_source();
			long bootAddress = chip.bootAddress();
			long nmiAddress = chip.nmiAddress();
			
			try {
				MemoryBlock chipMemoryBlock;
				String entryFlag = ""; //$NON-NLS-1$
				
				if (chip.isDefined()) {
					// map in as base (not overlay) when an entry point exists, otherwise as overlay
					chipMemoryBlock = MemoryBlockUtils.createInitializedBlock(program, !chip.isEntry(), chipName, chipStartAddress, chipBytes, 0, chipSize, chipComment, chipSource, r, w, x, log);
					
					AddressSpace chipAddressSpace = af.getAddressSpace(chipName);
					if (chipAddressSpace == null) {
						chipAddressSpace = af.getDefaultAddressSpace();
					}
					Namespace chipNamespace = symbolTable.getNamespace(chipAddressSpace.getAddress(chipStart));
					
					if (chip.isEntry()) {
						entryFlag += String.format(" BOOT = 0x%04x RESET = 0x%04x", bootAddress, nmiAddress); //$NON-NLS-1$
						
						// reset address space to default when chip is entry
						chipAddressSpace = af.getDefaultAddressSpace();
						chipNamespace = symbolTable.getNamespace(chipAddressSpace.getAddress(chipStart));
						
						Address bootSymbolAddress = chipAddressSpace.getAddress(bootAddress);
						Address nmiSymbolAddress = chipAddressSpace.getAddress(nmiAddress);
						//log.appendMsg(String.format("BOOT: %s\tRESET: %s", bootSymbolAddress, resetSymbolAddress));
						String bootSymbolName = String.format("%s_BOOT", chipName); //$NON-NLS-1$
						String nmiSymbolName = String.format("%s_NMI", chipName); //$NON-NLS-1$
						
						Address bootVectorAddress = chipAddressSpace.getAddress(0x8000);
						Address nmiVectorAddress = chipAddressSpace.getAddress(0x8002);
						Address signatureAddress = chipAddressSpace.getAddress(0x8004);
						
						try {
							CommodoreUtils.createVectorAddress(bootSymbolName+"_VECTOR", bootVectorAddress, chipNamespace, symbolTable, program, log);
							CommodoreUtils.createVectorAddress(nmiSymbolName+"_VECTOR", nmiVectorAddress, chipNamespace, symbolTable, program, log);
							DataUtilities.createData(program, signatureAddress, new ArrayDataType(new CharDataType(), 5, 1), 5, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
						} catch (InvalidInputException | CodeUnitInsertionException e) {
							log.appendMsg(String.format("Error creating cart startup data: %s", e.getMessage()));
						}
						
						try {
							symbolTable.createLabel(bootSymbolAddress, bootSymbolName, chipNamespace, SourceType.IMPORTED);
							symbolTable.addExternalEntryPoint(bootSymbolAddress);
							
						} catch (InvalidInputException e) {
							log.appendMsg(String.format("Error creating symbol \"%s\": %s", bootSymbolName, e.getMessage()));
						}
						try {
							symbolTable.createLabel(nmiSymbolAddress, nmiSymbolName, chipNamespace, SourceType.IMPORTED);
							symbolTable.addExternalEntryPoint(nmiSymbolAddress);
						} catch (InvalidInputException e) {
							log.appendMsg(String.format("Error creating symbol \"%s\": %s", nmiSymbolName, e.getMessage()));
						}
					}
					
					if (chip.containsResetVector()) {
						String nmiSymbolName = String.format("%s_NMI", chipName); //$NON-NLS-1$
						String resetSymbolName = String.format("%s_RESET", chipName); //$NON-NLS-1$
						String irqSymbolName = String.format("%s_IRQ", chipName); //$NON-NLS-1$
						Address nmiSymbolAddress = chipAddressSpace.getAddress(0xFFFA);
						Address resetSymbolAddress = chipAddressSpace.getAddress(0xFFFC);
						Address irqSymbolAddress = chipAddressSpace.getAddress(0xFFFE);
						try {
							long nmiAddr = CommodoreUtils.createVectorAddress(nmiSymbolName, nmiSymbolAddress, chipNamespace, symbolTable, program, log);
							entryFlag += String.format(" NMI=0x%04x", nmiAddr); //$NON-NLS-1$
							
							long resetAddr = CommodoreUtils.createVectorAddress(resetSymbolName, resetSymbolAddress, chipNamespace, symbolTable, program, log);
							entryFlag += String.format(" RESET=0x%04x", resetAddr); //$NON-NLS-1$
							
							long irqAddr = CommodoreUtils.createVectorAddress(irqSymbolName, irqSymbolAddress, chipNamespace, symbolTable, program, log);
							entryFlag += String.format(" IRQ=0x%04x", irqAddr); //$NON-NLS-1$
							
							
						} catch (InvalidInputException e) {
							log.appendMsg(String.format("Error creating symbol \"%s\": %s", irqSymbolName, e.getMessage()));
						}
					}
										
				} else {
					chipMemoryBlock = MemoryBlockUtils.createUninitializedBlock(program, true, chipName, chipStartAddress, chipSize, chipComment, chipSource, r, w, x, log);					
				}
				log.appendMsg(String.format("CHIP: %s (%s) at 0x%04x (0x%04x)%s", chipName, chipSource, chipStart, chipSize, entryFlag));
				chipMemoryBlock.setSourceName(chipSource);
				
			} catch (AddressOverflowException e) {
				log.appendMsg(e.getMessage());				
			}
			
		}
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

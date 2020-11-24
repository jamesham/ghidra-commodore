package commodoreloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class CommodoreChipHeader implements StructConverter, MemoryLoadable {
	
	private static String name = "CommodoreChip_Hdr"; //$NON-NLS-1$
	private static final String CHIP_MAGIC = "CHIP"; //$NON-NLS-1$
	private static final byte[] CHIP_BOOT_MARKER = { (byte) 0xc3, (byte) 0xc2, (byte) 0xcd, 0x38, 0x30 };
	
	private static final int CHIP_MAGIC_LEN = 4;
	private static final short CHIP_TYPE_ROM = 0;
	private static final short CHIP_TYPE_RAM = 1;
	private static final short CHIP_TYPE_EEPROM = 2;
	
	private String chip_magic_str;
	private long chip_length;
	private int chip_type;
	private int chip_bank;
	private long chip_load_addr;
	private long chip_image_size;
	//private byte[] chip_data;
	private long chip_data_offset;
	private long chip_file_offset;
	private FileBytes chip_file_bytes;
	private String chip_source;
	
	private Structure headerStructure;
	
	private BinaryReader reader;
	private CommodoreCartridgeHeader cart;
	private boolean parsed = false;
	private boolean chipContainsBootMarker = false;
	private long chipBootAddress = -1;
	private long chipResetAddress = -1;
	
	public static CommodoreChipHeader createCommodoreChipHeader(FactoryBundledWithBinaryReader reader, CommodoreCartridgeHeader cart, MessageLog log)
			throws IOException, CommodoreException {
		CommodoreChipHeader chipHeader = (CommodoreChipHeader) reader.getFactory().create(CommodoreChipHeader.class);
		chipHeader.initCommodoreChipHeader(reader, cart, log);
		return chipHeader;
	}
	
	protected void initCommodoreChipHeader(BinaryReader read, CommodoreCartridgeHeader crt, MessageLog log) 
			throws IOException, CommodoreException {
		this.reader = read;
		this.cart = crt;
		this.parsed = false;
		
		chip_file_offset = reader.getPointerIndex();
		boolean readerIsLittleEndian = reader.isLittleEndian();
		chip_magic_str = reader.readNextAsciiString(CHIP_MAGIC_LEN);
		
		if (!(chip_magic_str.equals(CHIP_MAGIC))) {
			throw new CommodoreException("Not a valid Commodore Cart Chip - Wrong Magic - Got: '" + chip_magic_str + "' (" + chip_magic_str.length() + ")" );
		}
		
		chip_length = reader.readNextInt() & 0xffffffff;
		chip_type = reader.readNextShort() & 0xffff;
		
		if (!(chip_type == CHIP_TYPE_ROM || chip_type == CHIP_TYPE_RAM || chip_type == CHIP_TYPE_EEPROM)) {
			throw new CommodoreException("Not a valid Commodore Cart Chip - Unrecognized Chip Type: " + chip_type);
		}
		
		chip_bank = reader.readNextShort() & 0xffff;
		chip_load_addr = reader.readNextShort() & 0xffff;
		chip_image_size = reader.readNextShort() & 0xffff;
		chip_data_offset = reader.getPointerIndex();
		
		try {
			if (chip_type != CHIP_TYPE_RAM && chip_image_size >= 9) {
				reader.setLittleEndian(true);
				chipBootAddress = reader.readNextShort() & 0xffff;
				chipResetAddress = reader.readNextShort() & 0xffff;
				byte[] chipBootMarker = reader.readNextByteArray(5);				
				chipContainsBootMarker = Arrays.equals(chipBootMarker,CHIP_BOOT_MARKER);
			}
		} finally {
			reader.setLittleEndian(readerIsLittleEndian);
		}
		
		if (!chipContainsBootMarker) {
			chipBootAddress = chipResetAddress = -1;
		}
		
		reader.setPointerIndex(chip_file_offset + chip_length);		
	}
	
	public void parse(Program program, TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
		if (reader == null) {
			throw new IOException("Commodore Cartridge binary reader is null!");
		}
		if (parsed) {
			return;
		}
		
		ByteProvider byteProvider = reader.getByteProvider();
		chip_source = byteProvider.getName();
		
		if (chip_type == CHIP_TYPE_ROM || chip_type == CHIP_TYPE_EEPROM) {
			try (InputStream fileIn = byteProvider.getInputStream(0)) {
				chip_file_bytes = MemoryBlockUtils.createFileBytes(program, byteProvider, chip_data_offset, chip_length, monitor); 
			}
		} else {
			chip_file_bytes = null;
		}
		
		parsed = true;		
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		if (headerStructure != null) {
			return headerStructure;
		}
		
		headerStructure = new StructureDataType(new CategoryPath("/Commodore"), name, 0); //$NON-NLS-1$
		headerStructure.add(STRING, chip_magic_str.length(), "chip_magic_str", null); //$NON-NLS-1$
		headerStructure.add(DWORD, "chip_length", null); //$NON-NLS-1$
		headerStructure.add(WORD, "chip_type", null); //$NON-NLS-1$
		headerStructure.add(WORD, "chip_bank", null); //$NON-NLS-1$
		headerStructure.add(WORD, "chip_load_addr", null); //$NON-NLS-1$
		headerStructure.add(WORD, "chip_image_size", null); //$NON-NLS-1$
		
		return headerStructure;
	}

	public String getChip_magic_str() {
		return chip_magic_str;
	}

	public long getChip_length() {
		return chip_length;
	}

	public int getChip_type() {
		return chip_type;
	}

	public int getChip_bank() {
		return chip_bank;
	}

	public long getChip_load_addr() {
		return chip_load_addr;
	}

	public long getChip_image_size() {
		return chip_image_size;
	}
	
	public FileBytes getChip_filebytes() {
		return chip_file_bytes;
	}
	
	public boolean isReadable() {
		return true;
	}
	
	public boolean isExecutable() {
		return true;
	}
	
	public boolean isWritable() {
		if (chip_type == CHIP_TYPE_ROM) {
			return false;
		}

		return true;
	}
	
	public boolean isDefined() {
		if (chip_type == CHIP_TYPE_RAM) {
			return false;
		}

		return true;
	}
	
	public boolean containsResetVector() {
		if ((chip_load_addr <= 0xfffc) && ((chip_load_addr + chip_image_size) >= 0x10000)) {
			return true;
		}
		
		return false;
	}
	
	public String chipTypeName() {
		switch (chip_type) {
			case CHIP_TYPE_ROM:
				return "ROM"; //$NON-NLS-1$
			case CHIP_TYPE_RAM:
				return "RAM"; //$NON-NLS-1$
			case CHIP_TYPE_EEPROM:
				return "EEPROM"; //$NON-NLS-1$
			default:
				return "UNKNOWN"; //$NON-NLS-1$
		}
	}
	
	public String get_chip_source() {
		return String.format("%s:%x", chip_source, chip_file_offset);  //$NON-NLS-1$
	}
	
	public long get_chip_data_offset() {
		return chip_data_offset;
	}

	public CommodoreCartridgeHeader getCart() {
		return cart;
	}
	
	public boolean isEntry() {
		// cannot map cart ROMs if EXROM and GAME are both high (system default)
		if (cart.getCart_exrom_status() == 1 && cart.getCart_game_status() == 1) {
			return false;
		}
		
		if (chip_load_addr == 0x8000 && chipContainsBootMarker) {
			return true;
		}
		
		return false;
	}
	
	public boolean isBootable() {
		return (isEntry() || containsResetVector());
	}
	
	public long bootAddress() {
		return chipBootAddress;
	}
	
	public long resetAddress() {
		return chipResetAddress;
	}
	
	public long get_chip_source_offset() {
		return chip_file_offset;
	}

}

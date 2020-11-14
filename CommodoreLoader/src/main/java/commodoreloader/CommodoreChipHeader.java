package commodoreloader;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class CommodoreChipHeader implements StructConverter, MemoryLoadable {
	
	private static String name = "CommodoreChip_Hdr";
	private static final String CHIP_MAGIC = "CHIP";
	
	private static final int CHIP_MAGIC_LEN = 4;
	
	private String chip_magic_str;
	private int chip_length;
	private short chip_type;
	private short chip_bank;
	private short chip_load_addr;
	private short chip_image_size;
	
	private Structure headerStructure;
	
	private FactoryBundledWithBinaryReader reader;
	private CommodoreCartridgeHeader cart;
	
	public static CommodoreChipHeader createCommodoreChipHeader(FactoryBundledWithBinaryReader reader, CommodoreCartridgeHeader cart)
			throws IOException {
		CommodoreChipHeader chipHeader = (CommodoreChipHeader) reader.getFactory().create(CommodoreChipHeader.class);
		chipHeader.initCommodoreChipHeader(reader, cart);
		return chipHeader;
	}
	
	protected void initCommodoreChipHeader(FactoryBundledWithBinaryReader read, CommodoreCartridgeHeader crt) 
			throws IOException {
		this.reader = read;
		this.cart = crt;
		
		chip_magic_str = reader.readNextAsciiString(CHIP_MAGIC_LEN);
		chip_length = reader.readNextInt();
		chip_type = reader.readNextShort();
		chip_bank = reader.readNextShort();
		chip_load_addr = reader.readNextShort();
		chip_image_size = reader.readNextShort();
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		if (headerStructure != null) {
			return headerStructure;
		}
		
		headerStructure = new StructureDataType(new CategoryPath("/Commodore"), name, 0);
		headerStructure.add(STRING, chip_magic_str.length(), "chip_magic_str", null);
		headerStructure.add(DWORD, "chip_length", null);
		headerStructure.add(WORD, "chip_type", null);
		headerStructure.add(WORD, "chip_bank", null);
		headerStructure.add(WORD, "chip_load_addr", null);
		headerStructure.add(WORD, "chip_image_size", null);
		
		return headerStructure;
	}

	public String getChip_magic_str() {
		return chip_magic_str;
	}

	public int getChip_length() {
		return chip_length;
	}

	public short getChip_type() {
		return chip_type;
	}

	public short getChip_bank() {
		return chip_bank;
	}

	public short getChip_load_addr() {
		return chip_load_addr;
	}

	public short getChip_image_size() {
		return chip_image_size;
	}

	public CommodoreCartridgeHeader getCart() {
		return cart;
	}

}

package commodoreloader;

import java.io.IOException;
import java.util.ArrayList;

import org.apache.commons.lang3.StringUtils;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class CommodoreCartridgeHeader implements StructConverter {
	
	private static String name = "CommodoreCart_Hdr";
	private static final String CART_MAGIC = "C64 CARTRIDGE   ";
	private static final short CART_VERSION_0100 = 0x0100;
	
	private static final int CART_MAGIC_LEN = 16;
	private static final int CART_RESERVED_LEN = 6;
	private static final int CART_NAME_LEN = 32;
	
	private String cart_magic_str;
	private int cart_header_len;
	private short cart_version;
	private short cart_hardware_type;
	private byte cart_exrom_status;
	private byte cart_game_status;
	private byte[] cart_reserved;
	private String cart_name;
	
	private Structure headerStructure;
	
	private CommodoreChipHeader[] chipHeaders = new CommodoreChipHeader[0];
	
	private FactoryBundledWithBinaryReader reader;
	private int chipCount;
	private boolean parsed;
	private boolean parsedChips;
	private CommodoreCartridgeHardwareType cart_hw_type;

	public static CommodoreCartridgeHeader createCommodoreCartridgeHeader(GenericFactory factory, ByteProvider provider)
			throws CommodoreException {
		CommodoreCartridgeHeader cartHeader = (CommodoreCartridgeHeader) factory.create(CommodoreCartridgeHeader.class);
		cartHeader.initCommodoreCartridgeHeader(factory, provider);
		return cartHeader;
	}
	
	protected void initCommodoreCartridgeHeader(GenericFactory factory, ByteProvider provider) 
			throws CommodoreException {
		
		try {
			reader = new FactoryBundledWithBinaryReader(factory, provider, false);
			
			byte[] magic_bytes = reader.readNextByteArray(CART_MAGIC_LEN);
			cart_magic_str = new String(magic_bytes);
			if (!(cart_magic_str.equals(CART_MAGIC))) {
				throw new CommodoreException("Not a valid Commodore Cartridge - Wrong Magic - Got: '" + cart_magic_str + "' (" + cart_magic_str.length() + ")" );
			}
			
			cart_header_len = reader.readNextInt();
			if (cart_header_len != 0x20 && cart_header_len != 0x40) {
				throw new CommodoreException("Not a valid Commodore Cartridge - Invalid Header Length");
			}			
			
			cart_version = reader.readNextShort();
			if (cart_version != CART_VERSION_0100) {
				throw new CommodoreException("Not a valid Commodore Cartridge - Unknown Version");
			}
			
			cart_hardware_type = reader.readNextShort();
			if (cart_hardware_type > CommodoreCartridgeHardwareType.getMaxId()) {
				throw new CommodoreException("Not a valid Commodore Cartridge - Invalid Hardward Type");
			}
			cart_hw_type = CommodoreCartridgeHardwareType.fromId(cart_hardware_type);
			
			cart_exrom_status = reader.readNextByte();
			if (cart_exrom_status != 0 && cart_exrom_status != 1) {
				throw new CommodoreException("Not a valid Commodore Cartridge - Invalid EXROM Line Status");
			}
			
			cart_game_status = reader.readNextByte();
			if (cart_game_status != 0 && cart_game_status != 1) {
				throw new CommodoreException("Not a valid Commodore Cartridge - Invalid GAME Line Status");
			}
			
			cart_reserved = reader.readNextByteArray(CART_RESERVED_LEN);
			
			if (cart_header_len == 0x40) {
				cart_name = reader.readNextAsciiString(CART_NAME_LEN);
			} else {
				cart_name = StringUtils.repeat(" ", CART_NAME_LEN);
			}
		
		} catch (IOException e) {
			throw new CommodoreException("Not a valid Commodore Cartridge header - I/O Error");
		}
	}
	
	public void parse() throws IOException {
		if (reader == null) {
			throw new IOException("Commodore Cartridge binary reader is null!");
		}
		if (parsed) {
			return;
		}
		
		parseChips();
		parsed = true;
	}
	
	protected void parseChips() throws IOException {
		if (reader == null) {
			throw new IOException("Commodore Cartridge binary reader is null!");
		}
		if (parsedChips) {
			return;
		}
		
		ArrayList<CommodoreChipHeader> chipHeaderList = new ArrayList<>();
		
		while (reader.getPointerIndex() < reader.length()) {
			CommodoreChipHeader chip = CommodoreChipHeader.createCommodoreChipHeader(reader, this);
			chipHeaderList.add(chip);
		}
		
		parsedChips = true;
		chipCount = chipHeaderList.size();
		chipHeaders = new CommodoreChipHeader[chipCount];
		chipHeaderList.toArray(chipHeaders);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		if (headerStructure != null) {
			return headerStructure;
		}
		
		headerStructure = new StructureDataType(new CategoryPath("/Commodore"), name, 0);
		headerStructure.add(STRING, cart_magic_str.length(), "cart_magic_str", null);
		headerStructure.add(DWORD, "cart_header_len", null);
		headerStructure.add(WORD, "cart_version", null);
		headerStructure.add(WORD, "cart_hardware_type", null);
		headerStructure.add(BYTE, "cart_exrom_status", null);
		headerStructure.add(BYTE, "cart_game_status", null);
		headerStructure.add(new ArrayDataType(BYTE,CART_RESERVED_LEN,1), "cart_reserved", null);
		headerStructure.add(STRING, cart_name.length(), "cart_name", null);		
		
		return headerStructure;
	}
	
	public String getCart_version_str() {
		return String.format("%02d.%02d", cart_version >> 8, cart_version & 0xff);
	}
	
	public String getCart_hardware_type_string() {
		return cart_hw_type.toString();
	}

	public String getCart_magic_str() {
		return cart_magic_str;
	}

	public int getCart_header_len() {
		return cart_header_len;
	}

	public short getCart_version() {
		return cart_version;
	}

	public short getCart_hardware_type() {
		return cart_hardware_type;
	}

	public byte getCart_exrom_status() {
		return cart_exrom_status;
	}

	public byte getCart_game_status() {
		return cart_game_status;
	}

	public byte[] getCart_reserved() {
		return cart_reserved;
	}

	public String getCart_name() {
		return cart_name;
	}
	
	public int getCart_chip_count() {
		return chipCount;
	}

}
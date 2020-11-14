package commodoreloader;

public enum CommodoreCartridgeHardwareType {
	
	CART_HW_NORMAL((short) 0, "Normal Cartridge"),
	CART_HW_ACTION_REPLAY((short) 1, "Action Replay V5"),
	CART_HW_KCS_POWER((short) 2, "KCS Power Cartridge"),
	CART_HW_FINAL_III((short) 3, "The Final Cartridge III"),
	CART_HW_SIMONS_BASIC((short) 4, "Simons' BASIC"),
	CART_HW_OCEAN((short) 5, "Ocean"),
	CART_HW_EXPERT((short) 6, "Expert Cartridge"),
	CART_HW_FUNPLAY((short) 7, "Fun Play / Power Play"),
	CART_HW_SUPER_GAMES((short) 8, "Super Games"),
	CART_HW_ATOMIC_POWER((short) 9, "Atomic Power / Nordic Power"),
	CART_HW_EPYX_FASTLOAD((short) 10, "Epyx FastLoad"),
	CART_HW_WESTERMANN((short) 11, "Westermann Learning"),
	CART_HW_REX((short) 12, "REX 256k EPROM Cart"),
	CART_HW_FINAL_I((short) 13, "The Final Cartridge"),
	CART_HW_MAGIC_FORMEL((short) 14, "Magic Formel"),
	CART_HW_GS((short) 15, "C64 Games System"),
	CART_HW_WARPSPEED((short) 16, "Warp Speed"),
	CART_HW_DINAMIC((short) 17, "Dinamic"),
	CART_HW_ZAXXON((short) 18, "Zaxxon"),
	CART_HW_MAGIC_DESK((short) 19, "Magic Desk / Domark / Hes Australia"),
	CART_HW_SUPER_SNAPSHOT_V5((short) 20, "Super Snapshot V5"),
	CART_HW_COMAL80((short) 21, "Comal 80"),
	CART_HW_STRUCTURED_BASIC((short) 22, "Structured BASIC"),
	CART_HW_ROSS((short) 23, "ROSS"),
	CART_HW_DELA_EP64((short) 24, "Dela EP64"),
	CART_HW_DELA_EP7x8((short) 25, "Dela EP7x8"),
	CART_HW_DELA_EP256((short) 26, "Dela EP256"),
	CART_HW_REX_EP256((short) 27, "REX 256k EPROM Cart"),
	CART_HW_MIKRO_ASSEMBLER((short) 28, "Mikro Assembler"),
	CART_HW_FINAL_PLUS((short) 29, "Final Cartridge Plus"),
	CART_HW_ACTION_REPLAY4((short) 30, "Action Replay MK4"),
	CART_HW_STARDOS((short) 31, "Stardos"),
	CART_HW_EASYFLASH((short) 32, "EasyFlash"),
	CART_HW_EASYFLASH_XBANK((short) 33, "EasyFlash Xbank"),
	CART_HW_CAPTURE((short) 34, "Capture"),
	CART_HW_ACTION_REPLAY3((short) 35, "Action Replay MK3"),
	CART_HW_RETRO_REPLAY((short) 36, "Retro Replay"),
	CART_HW_MMC64((short) 37, "MMC64"),
	CART_HW_MMC_REPLAY((short) 38, "MMC Replay"),
	CART_HW_IDE64((short) 39, "IDE64"),
	CART_HW_SUPER_SNAPSHOT((short) 40, "Super Snapshot V4"),
	CART_HW_IEEE488((short) 41, "IEEE-488 Interface"),
	CART_HW_GAME_KILLER((short) 42, "Game Killer"),
	CART_HW_P64((short) 43, "Prophet64"),
	CART_HW_EXOS((short) 44, "EXOS"),
	CART_HW_FREEZE_FRAME((short) 45, "Freeze Frame"),
	CART_HW_FREEZE_MACHINE((short) 46, "Freeze Machine"),
	CART_HW_SNAPSHOT64((short) 47, "Snapshot 64"),
	CART_HW_SUPER_EXPLODE_V5((short) 48, "Super Explode V5.0"),
	CART_HW_MAGIC_VOICE((short) 49, "Magic Voice"),
	CART_HW_ACTION_REPLAY2((short) 50, "Action Replay MK2"),
	CART_HW_MACH5((short) 51, "MACH 5"),
	CART_HW_DIASHOW_MAKER((short) 52, "Diashow-Maker"),
	CART_HW_PAGEFOX((short) 53, "Pagefox"),
	CART_HW_KINGSOFT((short) 54, "Kingsoft"),
	CART_HW_SILVERROCK_128((short) 55, "Silverrock 128K Cartridge"),
	CART_HW_FORMEL64((short) 56, "Formel 64"),
	CART_HW_RGCD((short) 57, "RGCD"),
	CART_HW_RRNETMK3((short) 58, "RR-Net MK3"),
	CART_HW_EASYCALC((short) 59, "Easy Calc Result"),
	CART_HW_GMOD2((short) 60, "GMod2"),
	CART_HW_MAX_BASIC((short) 61, "MAX Basic");
	
	private String cartHwTypeName;
	private short id;
	private static CommodoreCartridgeHardwareType[] cachedValues = null;
	
	private CommodoreCartridgeHardwareType(short id, String typeName) {
		this.id = id;
		this.cartHwTypeName = typeName;
	}
	
	@Override
	public String toString() {
		return this.cartHwTypeName;
	}
	
	public short getId() {
		return id;
	}
	
	public static short getMaxId() {
		return CommodoreCartridgeHardwareType.CART_HW_MAX_TYPE().getId();
	}
	
	public static CommodoreCartridgeHardwareType fromId(short id) {
		if (cachedValues == null) {
			cachedValues = CommodoreCartridgeHardwareType.values();
		}		
		
		return cachedValues[id];
	}
	
	public static CommodoreCartridgeHardwareType CART_HW_MAX_TYPE() {
		if (cachedValues == null) {
			cachedValues = CommodoreCartridgeHardwareType.values();
		}
		
		return cachedValues[cachedValues.length - 1];
	}

}

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class GetExtension {
	public static void main(String[] argv) {
		BufferedReader br = null;
		int[] opcodes = new int[15];
		String line;
		try {
			br = new BufferedReader(new FileReader(argv[0]));
			while ((line = br.readLine()) != null) {
				String[] splits = line.split(" ");
				int index = 0;
				while (splits[index].length() == 0)
					++index;
				for (int i = 0; i < 15; ++i) {
					if (splits[index].equals(extensionNames[i])) {
						int before = line.indexOf("opcode: ");
						before += "opcode: ".length();
						opcodes[i] = Integer.parseInt(line.substring(before,
								before + 3));
						System.out.println("Find extension:" + splits[index]
								+ "  opcode:" + opcodes[i]);
						break;
					}
				}
			}
			System.out.println ("======================================");
			System.out.println ("Now put the following defines into util.H");
			System.out.println ("======================================");
			for (int i = 0; i < 15; ++i) {
				System.out.println ("#define " + defines[i] + " " + opcodes[i]);
				if (opcodes[i] < 100) {
					System.out.println ("Error!!!! missing an extension!");
					System.out.println ("Check if you have the graphic driver installed???");
					break;
				}
			} 
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

	private static String[] defines = { "XE_EVENT_EXTENSION", "XE_SHAPE",
			"XE_MIT_SHM", "XE_XInputExtension", "XE_BIG_REQUESTS", "XE_SYNC",
			"XE_XKEYBOARD", "XE_XFIXES", "XE_RENDER", "XE_RANDR",
			"XE_XINERAMA", "XE_Composite", "XE_DAMAGE", "XE_DRI2", "XE_SGI_GLX" };
	private static String[] extensionNames = { "Generic", "SHAPE", "MIT-SHM",
			"XInputExtension", "BIG-REQUESTS", "SYNC", "XKEYBOARD", "XFIXES",
			"RENDER", "RANDR", "XINERAMA", "Composite", "DAMAGE", "DRI2",
			"SGI-GLX" };
}

package run;

import hash.SHA256;

/**
 *
 * @author moles
 */
public class Runner {
     /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String test="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        SHA256 sha=new SHA256();
        byte[] data = test.getBytes();
        String digest = sha.digest(test);
        System.out.println(digest);
    }
}

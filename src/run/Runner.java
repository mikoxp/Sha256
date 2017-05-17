package run;

import hash.SHA256;
import java.math.BigInteger;
import java.util.Arrays;

/**
 *
 * @author moles
 */
public class Runner {
     /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String test="12345";
        SHA256 sha256=new SHA256();
        System.out.println(sha256.update(test));
    }
}

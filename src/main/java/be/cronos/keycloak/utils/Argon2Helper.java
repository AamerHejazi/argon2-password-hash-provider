package be.cronos.keycloak.utils;

import be.cronos.keycloak.enums.Argon2Variant;
import be.cronos.keycloak.exceptions.Argon2RuntimeException;
import de.mkammerer.argon2.Argon2Factory;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.jboss.logging.Logger;
import org.keycloak.models.credential.PasswordCredentialModel;
import de.mkammerer.argon2.Argon2;

import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;
import java.util.Base64;

import static de.mkammerer.argon2.Argon2Factory.Argon2Types.*;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2Helper {
    private static final Logger LOG = Logger.getLogger(Argon2Helper.class);

    private Argon2Helper() {
        throw new IllegalStateException("Helper class");
    }

    public static String hashPassword(String rawPassword, byte[] salt, Argon2Variant argon2Variant, int version,
                                      int iterations, int parallelism, int memoryLimit, int hashLength) {

        if (rawPassword == null) throw new Argon2RuntimeException("Password can't be empty");

        // Validate whether the version is valid
        if (version != org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_10 && version != org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13)
            throw new Argon2RuntimeException("Invalid version");

        LOG.debugf("Using the following Argon2 settings:");
        LOG.debugf("\tArgon2 Variant: %s", argon2Variant.getArgon2VariantStringRepr());
        LOG.debugf("\tIterations: %d", iterations);
        LOG.debugf("\tVersion: %h", version);
        LOG.debugf("\tParallelism: %d", parallelism);
        LOG.debugf("\tMemory limit: %d", memoryLimit);
        LOG.debugf("\tHash Length: %d", hashLength);
        LOG.debugf("\tSalt Length: %d", salt.length);

        try {
            // Construct the Argon2 Parameters Builder
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(argon2Variant.getArgon2BouncyCastle())
                    .withSalt(salt)
                    .withVersion(version)
                    .withIterations(iterations)
                    .withParallelism(parallelism)
                    .withMemoryAsKB(memoryLimit);

            // Initialize BouncyCastle's Argon2 generator
            Argon2BytesGenerator generator = new Argon2BytesGenerator();

            // Initialize the digest generator
            generator.init(builder.build());

            // Digest bytes result output
            byte[] result = new byte[hashLength];

            // Keep track of hashing runtime
            long start = System.currentTimeMillis();

            // Perform the hashing
            generator.generateBytes(rawPassword.toCharArray(), result, 0, result.length);

            // Stop timing
            long end = System.currentTimeMillis();

            // Print the hashing runtime for debug purposes
            LOG.debugf("Hashing runtime was %d milliseconds (%d seconds).", end-start, (end-start)/1000);

            // Return an encoded representation of the argon2 password hash
            return String.format("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
                    argon2Variant.getArgon2VariantStringRepr(),
                    version,
                    memoryLimit,
                    iterations,
                    parallelism,
                    Base64.getEncoder().withoutPadding().encodeToString(salt),
                    Base64.getEncoder().withoutPadding().encodeToString(result)
            );
        } catch (Exception e) {
            LOG.errorf("Something went wrong while hashing the password, message = '%s'", e.getMessage());
        }
        throw new Argon2RuntimeException("Something went wrong while securing the password.");
    }

    public static boolean verifyPassword(String rawPassword, PasswordCredentialModel credential) {
        // Get the Argon2 parameters of the credential, should be something like:
        // $argon2i$v=19$m=65535,t=30,p=4$JQUxqirAz7+Em0yM1ZiDFA$LhqtL0XPGESfeHb4lI2XnV4mSZacWGQWANKtvIVVpy4
        // Retrieve the stored encoded password
        String storedEncodedPassword = credential.getPasswordSecretData().getValue();
        System.out.println("hashed value is "+storedEncodedPassword);
        // Retrieved the salt
        byte[] salt = credential.getPasswordSecretData().getSalt();
        System.out.println("The salt is "+DatatypeConverter.printBase64Binary(salt));
        // Extract all the stored parameters

        Argon2EncodingUtils.Argon2Parameters argon2Parameters = Argon2EncodingUtils.extractArgon2ParametersFromEncodedPassword(storedEncodedPassword);

        // Extract the digest
        String storedPasswordDigest = Argon2EncodingUtils.extractDigest(storedEncodedPassword);
        if (storedPasswordDigest == null) {
            LOG.errorf("There's something wrong with the stored password encoding, couldn't find the actual hash.");
            throw new Argon2RuntimeException("Something went wrong.");
        }

        System.out.println(argon2Parameters.getArgon2Variant().toString());
        String argon2Type = argon2Parameters.getArgon2Variant().toString();
        Argon2Factory.Argon2Types realArgon2Types;
        switch (argon2Type){
            case "ARGON2I":
                realArgon2Types = ARGON2i;
                break;
            case "ARGON2D":
                realArgon2Types = ARGON2d;
                break;
            case "ARGON2ID":
                realArgon2Types = ARGON2id;
                break;
            default:
                throw new IllegalArgumentException("No enum constant de.mkammerer.argon2.Argon2Factory.Argon2Types."+argon2Type );
        }
        //System.out.println("This is me " + Argon2Factory.Argon2Types.valueOf());
        System.out.println("The salt length is "+ argon2Parameters.getSaltLength());
        System.out.println("The salt hash is "+argon2Parameters.getHashLength());

        Argon2 argon2 = Argon2Factory.createAdvanced(realArgon2Types,argon2Parameters.getSaltLength(),argon2Parameters.getHashLength());

        // Compare the 2 digests using constant-time comparison
        boolean samePassword = argon2.verify(storedEncodedPassword, rawPassword);
        System.out.println("Are The two passwords are same? "+samePassword);
        LOG.debugf("Password match = %s", String.valueOf(samePassword));

        return samePassword;
    }

    public static byte[] getSalt(int saltLength) {
        LOG.debugf("Generating salt with length '%d'.", saltLength);
        byte[] buffer = new byte[saltLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }
}

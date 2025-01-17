package be.cronos.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2ParallelismPasswordPolicyProviderFactory extends Argon2GenericPolicyProviderFactory {
    public static final String ID = "argon2Parallelism";
    public static final int DEFAULT_PARALLELISM = 2;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "Argon2 Parallelism";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_PARALLELISM);
    }
}

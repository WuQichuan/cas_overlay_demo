package security;

import org.springframework.security.crypto.password.PasswordEncoder;
import utils.Encodes;


public class CustomPasswordEncoder implements PasswordEncoder {
    public static final String HASH_ALGORITHM = "SHA-1";
    public static final int HASH_INTERATIONS = 1024;
    public static final int SALT_SIZE = 8;
    @Override
    public String encode(CharSequence charSequence) {
        // 采用Jeeplus加密方式生成安全的密码
        byte[] salt = Digests.generateSalt(SALT_SIZE);
        // 生成随机的16位salt并经过1024次 sha-1 hash
        byte[] hashPassword = Digests.sha1(charSequence.toString().getBytes(), salt, HASH_INTERATIONS);
        return Encodes.encodeHex(salt)+Encodes.encodeHex(hashPassword);
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        //charSequence.toString()为明文密码，经加密后变为hashPassword
        byte[] salt = Encodes.decodeHex(s.substring(0,16));
        byte[] hashPassword = Digests.sha1(charSequence.toString().getBytes(), salt, HASH_INTERATIONS);
        //String s为数据库里的加密密码，返回s和hashPassword是否相等来判断密码是否匹配
        return s.equals(Encodes.encodeHex(salt)+Encodes.encodeHex(hashPassword));
    }
}

package com.c88.auth.constants;

import java.util.List;

public class KeyConstants {

    private KeyConstants() {
        throw new IllegalStateException("Utility class");
    }

    public static final List<String> NOT_VALID_IP = List.of("0:0:0:0:0:0:0:1", "127.0.0.1", "localhost");

}

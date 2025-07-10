package com.matthews.poc.cloudhsm.provider.userprovider;

import com.matthews.poc.cloudhsm.api.Session;

public record UserSession(String user, String clusterId) implements Session {
    public String key() {
        return user + "@" + clusterId;
    }
}

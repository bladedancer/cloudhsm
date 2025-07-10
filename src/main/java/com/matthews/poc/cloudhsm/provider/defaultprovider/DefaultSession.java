package com.matthews.poc.cloudhsm.provider.defaultprovider;

import com.matthews.poc.cloudhsm.api.Session;

public record DefaultSession(String clusterId) implements Session {
}

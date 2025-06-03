package com.matthews.poc.cloudhsm;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

import java.security.Key;
import java.util.Base64;

@Path("/key")
public class KeyController {
    @Inject
    ProviderService providerService;

    @GET
    @Path("{label}")
    public String getKey(@PathParam("label") String label) throws Exception {
        Key key = providerService.generateAESKey(256, label);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}

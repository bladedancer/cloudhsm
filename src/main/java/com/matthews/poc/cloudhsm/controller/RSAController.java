package com.matthews.poc.cloudhsm.controller;

import com.matthews.poc.cloudhsm.api.ProviderService;
import com.matthews.poc.cloudhsm.api.Session;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import java.security.KeyPair;

@Path("/rsa")
public class RSAController {
    @Inject
    @Named("UserProviderService")
    ProviderService providerService;

    @POST
    @Path("{label}")
    public Response createKey(@PathParam("label") String label,
                              @QueryParam("user") String user,
                              @QueryParam("pass") String pass,
                              @QueryParam("keysize") int keySize) throws Exception {
        Session session = providerService.login(user, pass);
        KeyPair key = providerService.generateRSAKey(session, keySize, label);
        if (key == null) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        return Response.ok(key.getPublic().getAlgorithm()).build();
    }
}

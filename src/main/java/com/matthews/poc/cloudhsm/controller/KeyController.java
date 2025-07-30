package com.matthews.poc.cloudhsm.controller;

import com.matthews.poc.cloudhsm.api.ProviderService;
import com.matthews.poc.cloudhsm.api.Session;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import java.security.Key;

@Path("/key")
public class KeyController {
    @Inject
    @Named("UserProviderService")
    ProviderService providerService;

    @GET
    public Response listKeys(@QueryParam("user") String user, @QueryParam("pass") String pass) throws Exception {
        Session session = providerService.login(user, pass);
        return Response.ok(providerService.listKeys(session)).build();
    }

    @GET
    @Path("{label}")
    public Response getKey(@PathParam("label") String label, @QueryParam("user") String user, @QueryParam("pass") String pass) throws Exception {
        Session session = providerService.login(user, pass);
        Key key = providerService.getKeyByLabel(session, label);
        if (key == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        return Response.ok(key).build();
    }

    @POST
    @Path("{label}")
    public Response createKey(@PathParam("label") String label, @QueryParam("user") String user, @QueryParam("pass") String pass) throws Exception {
        Session session = providerService.login(user, pass);
        Key key = providerService.generateAESKey(session, 256, label);
        if (key == null) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        return Response.ok(key.getAlgorithm()).build();
    }
}

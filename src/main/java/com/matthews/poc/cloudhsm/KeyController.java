package com.matthews.poc.cloudhsm;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;

import java.security.Key;

@Path("/key")
public class KeyController {
    @Inject
    ProviderService providerService;

    @GET
    public Response listKeys() throws Exception {
        return Response.ok(providerService.listKeys()).build();
    }

    @GET
    @Path("{label}")
    public Response getKey(@PathParam("label") String label) throws Exception {
        Key key = providerService.getKeyByLabel(label);
        if (key == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(key).build();
    }

    @POST
    @Path("{label}")
    public Response createKey(@PathParam("label") String label) throws Exception {
        Key key = providerService.generateAESKey(256, label);
        if (key == null) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        return Response.ok(key).build();
    }
}

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

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;

@Path("/mtls")
public class MTLSController {
    @Inject
    @Named("UserProviderService")
    ProviderService providerService;

    @POST
    @Path("/keystore")
    public Response createKeyStore(@QueryParam("user") String user, @QueryParam("pass") String pass, @QueryParam("label") String label) throws Exception {
        Session session = providerService.login(user, pass);
        String path = providerService.createKeystore(session, label);
        return Response.ok("Keystore created: " + path).build();
    }

    @GET
    public Response getKey(@QueryParam("user") String user, @QueryParam("pass") String pass, @QueryParam("label") String label) throws Exception {
        Session session = providerService.login(user, pass);
        SSLContext sslContext = providerService.getSSLContext(session, label);

        HttpClient httpClient = HttpClient.newBuilder().sslContext(sslContext).build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://multi-design.dev.10-128-144-140.nip.io:4443/mtls/hello?name=" + label))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        return Response.status(response.statusCode())
                .entity(response.body())
                .build();
    }
}

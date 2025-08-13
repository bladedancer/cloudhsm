package com.matthews.poc.cloudhsm.controller;

import com.matthews.poc.cloudhsm.api.ProviderService;
import com.matthews.poc.cloudhsm.api.Session;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URL;

@Slf4j
@Path("/mtls")
public class MTLSController {
    @ConfigProperty(name = "app.mtls.url")
    String mtlsUrl;

    @Inject
    @Named("UserProviderService")
    ProviderService providerService;

    @GET
    public Response getKey(@QueryParam("user") String user, @QueryParam("pass") String pass, @QueryParam("label") String label) throws Exception {
        Session session = providerService.login(user, pass);
        SSLContext sslContext = providerService.getSSLContext(session, label);

        URL url = new URL(String.format(mtlsUrl, label));
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setSSLSocketFactory(sslContext.getSocketFactory());
        con.connect();

        return Response.status(con.getResponseCode())
                .entity(con.getContent())
                .build();
    }
}

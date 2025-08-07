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
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;

@Slf4j
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

        URL url = new URL("https://multi-design.dev.10-128-144-140.nip.io:4443/mtls/hello?name=" + label);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setSSLSocketFactory(sslContext.getSocketFactory());
        con.connect();



        return Response.status(con.getResponseCode())
                .entity(con.getContent())
                .build();

//        HttpClient httpClient = HttpClient.newBuilder().sslContext(sslContext).build();
//
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(URI.create("https://multi-design.dev.10-128-144-140.nip.io:4443/mtls/hello?name=" + label))
//                .build();
//
//        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

//        String serverName = "multi-design.dev.10-128-144-140.nip.io";
//        int port = 4443;
//        String path = "/mtls/hello?name=" + label;
//
//        try {
//            SSLSocketFactory sf = sslContext.getSocketFactory();
//            SSLSocket socket = (SSLSocket)sf.createSocket(serverName, port);
//
//            log.info("Connected to " + socket.getRemoteSocketAddress());
//            OutputStream outToServer = socket.getOutputStream();
//
//            writeData(out);
//            out.flush();
//
//            InputStream inFromServer = client.getInputStream();
//
//
//
//            readData(in);
//            outToServer = client.getOutputStream();
//            out = new DataOutputStream(new BufferedOutputStream(outToServer));
//            writeData2(out);
//            out.flush();
//
//            Socket newClient = sf.createSocket(client, serverName, port, false);
//
//            client.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//        return Response.status(response.statusCode())
//                .entity(response.body())
//                .build();
    }
}

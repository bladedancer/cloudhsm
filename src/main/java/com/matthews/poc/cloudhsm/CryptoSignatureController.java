package com.matthews.poc.cloudhsm;

import jakarta.inject.Inject;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

@Path("/api/crypto")
@Slf4j
public class CryptoSignatureController {
    @Inject
    ProviderService providerService;

    @POST
    @Path("/verify")
    public Response verifySignature(@NotBlank String payload,
                                    @HeaderParam("X-Signature") @NotBlank String signature,
                                    @HeaderParam("X-Key-Id") @NotBlank String keyLabel,
                                    @HeaderParam("X-Algorithm") @DefaultValue("HmacSHA256") String algorithm) {
        try {
            boolean isValid = providerService.verifySignature(payload, keyLabel, algorithm, signature);
            return Response.ok(isValid ? "Valid Signature" : "Invalid Signature").build();
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException |
                UnrecoverableKeyException | InvalidKeyException | NoSuchProviderException e) {
            log.error("Signature verification failed", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Verification failed").build();
        }
    }

    @POST
    @Path("/sign")
    public Response signPayload(@NotBlank String payload,
                                @HeaderParam("X-Key-Id") @NotBlank String keyLabel,
                                @HeaderParam("X-Algorithm") @DefaultValue("HmacSHA256") String algorithm) {
        try{
        String signature = providerService.signPayload(payload, keyLabel, algorithm);
        return Response.ok(signature).build();
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException |
                 UnrecoverableKeyException | InvalidKeyException | NoSuchProviderException e) {
            log.error("Signing failed", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Signing failed").build();
        }
    }
}

package com.matthews.poc.cloudhsm;

import com.amazonaws.cloudhsm.jce.jni.AuthenticationStrategy;
import com.amazonaws.cloudhsm.jce.jni.UserType;
import com.amazonaws.cloudhsm.jce.provider.authentication.AuthenticationStrategyCallback;
import lombok.RequiredArgsConstructor;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

@RequiredArgsConstructor
public class ApplicationCallbackHandler implements CallbackHandler {
    private final UserType userType;
    private final String username;
    private final String password;

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof AuthenticationStrategyCallback asc) {
                try {
                    asc.setAuthenticationStrategy(AuthenticationStrategy.createUsernamePasswordStrategy(userType, username, password.toCharArray()));
                } catch (Exception e) {
                    throw new IOException(e);
                }
            }
        }
    }
}
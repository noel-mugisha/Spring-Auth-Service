package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.request.MfaDisableRequest;
import com.noel.springsecurity.dto.request.MfaEnableRequest;
import com.noel.springsecurity.dto.response.ApiMessageResponse;
import com.noel.springsecurity.dto.response.MfaRecoveryCodesResponse;
import com.noel.springsecurity.dto.response.MfaSetupResponse;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.services.IMfaService;
import com.noel.springsecurity.utils.IAuthenticationFacade;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MfaControllerTest {

    @Mock private IMfaService mfaService;
    @Mock private IAuthenticationFacade authenticationFacade;

    private MfaController mfaController;
    private User user;

    @BeforeEach
    void setUp() {
        mfaController = new MfaController(mfaService, authenticationFacade);
        user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("jane@example.com");
        when(authenticationFacade.getCurrentUser()).thenReturn(user);
    }

    @Test
    void setup_returnsTheSecretAndQrCodeForTheCurrentUser() {
        when(mfaService.setupMfa(user))
                .thenReturn(new IMfaService.MfaSetupResult("SECRET123", "data:image/png;base64,abc"));

        ResponseEntity<MfaSetupResponse> response = mfaController.setup();

        assertThat(response.getBody().secret()).isEqualTo("SECRET123");
        assertThat(response.getBody().qrCodeImageDataUri()).isEqualTo("data:image/png;base64,abc");
    }

    @Test
    void enable_returnsTheRecoveryCodesOnSuccess() {
        when(mfaService.enableMfa(user, "654321")).thenReturn(List.of("aaaa-bbbb", "cccc-dddd"));

        ResponseEntity<MfaRecoveryCodesResponse> response =
                mfaController.enable(new MfaEnableRequest("654321"));

        assertThat(response.getBody().recoveryCodes()).containsExactly("aaaa-bbbb", "cccc-dddd");
    }

    @Test
    void disable_delegatesToTheServiceWithTheCurrentUserAndPassword() {
        ResponseEntity<ApiMessageResponse> response =
                mfaController.disable(new MfaDisableRequest("correct-password"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().message()).contains("disabled");
        verify(mfaService).disableMfa(user, "correct-password");
    }
}
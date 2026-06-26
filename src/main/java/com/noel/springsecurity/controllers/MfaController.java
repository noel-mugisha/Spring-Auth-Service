package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.request.MfaDisableRequest;
import com.noel.springsecurity.dto.request.MfaEnableRequest;
import com.noel.springsecurity.dto.response.ApiMessageResponse;
import com.noel.springsecurity.dto.response.MfaRecoveryCodesResponse;
import com.noel.springsecurity.dto.response.MfaSetupResponse;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.services.IMfaService;
import com.noel.springsecurity.utils.IAuthenticationFacade;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final IMfaService mfaService;
    private final IAuthenticationFacade authenticationFacade;

    // returns a QR code (and the raw secret for manual entry)
    @PostMapping("/setup")
    public ResponseEntity<MfaSetupResponse> setup() {
        User user = authenticationFacade.getCurrentUser();
        IMfaService.MfaSetupResult result = mfaService.setupMfa(user);
        return ResponseEntity.ok(new MfaSetupResponse(result.secret(), result.qrCodeImageDataUri()));
    }

    // Confirm enrollment with a code from the authenticator app
    @PostMapping("/enable")
    public ResponseEntity<MfaRecoveryCodesResponse> enable(@Valid @RequestBody MfaEnableRequest request) {
        User user = authenticationFacade.getCurrentUser();
        var recoveryCodes = mfaService.enableMfa(user, request.code());
        return ResponseEntity.ok(new MfaRecoveryCodesResponse(recoveryCodes));
    }

    // Turn MFA off (requires the account password)
    @PostMapping("/disable")
    public ResponseEntity<ApiMessageResponse> disable(@Valid @RequestBody MfaDisableRequest request) {
        User user = authenticationFacade.getCurrentUser();
        mfaService.disableMfa(user, request.password());
        return ResponseEntity.ok(new ApiMessageResponse("MFA has been disabled for your account."));
    }
}
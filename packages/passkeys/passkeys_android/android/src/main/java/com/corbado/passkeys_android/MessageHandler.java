package com.corbado.passkeys_android;

import android.app.Activity;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.credentials.CreateCredentialResponse;
import androidx.credentials.CreatePublicKeyCredentialRequest;
import androidx.credentials.Credential;
import androidx.credentials.CredentialManager;
import androidx.credentials.CredentialManagerCallback;
import androidx.credentials.GetCredentialRequest;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.GetPublicKeyCredentialOption;
import androidx.credentials.PublicKeyCredential;
import androidx.credentials.exceptions.CreateCredentialCancellationException;
import androidx.credentials.exceptions.CreateCredentialException;
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException;
import androidx.credentials.exceptions.GetCredentialCancellationException;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.exceptions.NoCredentialException;
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException;
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException;

import com.corbado.passkeys_android.models.login.AllowCredentialType;
import com.corbado.passkeys_android.models.login.GetCredentialOptions;
import com.corbado.passkeys_android.models.signup.AuthenticatorSelectionType;
import com.corbado.passkeys_android.models.signup.CreateCredentialOptions;
import com.corbado.passkeys_android.models.signup.ExcludeCredentialType;
import com.corbado.passkeys_android.models.signup.PubKeyCredParamType;
import com.corbado.passkeys_android.models.signup.RelyingPartyType;
import com.corbado.passkeys_android.models.signup.UserType;
import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.tasks.Task;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

public class MessageHandler implements Messages.PasskeysApi {

    private static final String TAG = "MessageHandler";
    private static final String SYNC_ACCOUNT_NOT_AVAILABLE_ERROR = "Sync account could not be accessed. If you are running on an emulator, please restart that device (select 'Could boot now').";
    private static final String MISSING_GOOGLE_SIGN_IN_ERROR = "Please sign in with a Google account first to create a new passkey.";
    private static final String EXCLUDE_CREDENTIALS_MATCH_ERROR = "You can not create a credential on this device because one of the excluded credentials exists on the local device.";
    private static final String MISSING_CREATION_OPTIONS = "Please make sure you enable a passwords or passkeys provider in your device settings.";
    private static final String TIMEOUT_ERROR = "Passkey operation timed out, please try again";

    private final FlutterPasskeysPlugin plugin;
    // All CredentialManager callbacks are dispatched to the main thread so that
    // result delivery is single-threaded with lifecycle cancellation/timeout.
    private final Executor mainExecutor = r -> new Handler(Looper.getMainLooper()).post(r);

    private CancellationSignal currentCancellationSignal;
    private final Handler timeoutHandler = new Handler(Looper.getMainLooper());
    private Runnable timeoutRunnable;

    // Pending result references kept as fields so that cancelOnBackground() and the
    // timeout handler can deliver errors directly.  GMS CABLE (cross-device QR) does
    // NOT call onError after CancellationSignal.cancel() — confirmed by testing — so
    // we must deliver the error ourselves without waiting for the GMS callback.
    private Messages.Result<Messages.AuthenticateResponse> pendingAuthResult;
    private boolean authResultDelivered = false;
    private Messages.Result<Messages.RegisterResponse> pendingRegisterResult;
    private boolean registerResultDelivered = false;

    public MessageHandler(FlutterPasskeysPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public void canAuthenticate(@NonNull Messages.Result<Boolean> result) {
        Activity activity = plugin.requireActivity();
        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(activity.getApplicationContext());

        Task<Boolean> isAvailable = fido2ApiClient.isUserVerifyingPlatformAuthenticatorAvailable();
        isAvailable.addOnSuccessListener(result::success);
        isAvailable.addOnFailureListener(result::error);
    }

    @Override
    public void hasPasskeySupport(@NonNull Messages.Result<Boolean> result) {
        // Passkeys are supported on Android API 28 (Android 9.0) and above
        boolean hasSupport = android.os.Build.VERSION.SDK_INT >= 28;
        result.success(hasSupport);
    }

    @Override
    public void register(
            @NonNull String challenge,
            @NonNull Messages.RelyingParty relyingParty,
            @NonNull Messages.User user,
            @Nullable Messages.AuthenticatorSelection authenticatorSelection,
            @Nullable List<Messages.PubKeyCredParam> pubKeyCredParams,
            @Nullable Long timeout,
            @Nullable String attestation,
            @NonNull List<Messages.ExcludeCredential> excludeCredentials,
            @NonNull Messages.Result<Messages.RegisterResponse> result) {
        if (android.os.Build.VERSION.SDK_INT < 28) {
            result.error(new Messages.FlutterError("android-passkey-unsupported",
                    "Passkeys are only supported on Android API 28 and above.", null));
            return;
        }

        pendingRegisterResult = result;
        registerResultDelivered = false;

        UserType userType = new UserType(user.getName(), user.getDisplayName(), user.getId(), user.getIcon());
        RelyingPartyType relyingPartyType = new RelyingPartyType(relyingParty.getId(), relyingParty.getName());
        AuthenticatorSelectionType authSelectionType = null;
        if (authenticatorSelection != null) {
            authSelectionType = new AuthenticatorSelectionType(
                    authenticatorSelection.getAuthenticatorAttachment(), authenticatorSelection.getRequireResidentKey(),
                    authenticatorSelection.getResidentKey(), authenticatorSelection.getUserVerification());
        }
        List<PubKeyCredParamType> pubKeyCredParamsType = new ArrayList<>();
        if (pubKeyCredParams != null) {
            pubKeyCredParamsType = pubKeyCredParams.stream().map(p -> new PubKeyCredParamType(p.getType(), p.getAlg()))
                    .collect(Collectors.toList());
        }
        final List<ExcludeCredentialType> excludeCredentialsType = excludeCredentials.stream()
                .map(c -> new ExcludeCredentialType(c.getType(), c.getId())).collect(Collectors.toList());

        CreateCredentialOptions createCredentialOptions = new CreateCredentialOptions(
                challenge,
                relyingPartyType,
                userType,
                pubKeyCredParamsType,
                timeout,
                authSelectionType,
                attestation,
                excludeCredentialsType);

        try {
            String options = createCredentialOptions.toJSON().toString();

            Activity activity = plugin.requireActivity();
            CredentialManager credentialManager = CredentialManager.create(activity);
            CreatePublicKeyCredentialRequest createPublicKeyCredentialRequest = new CreatePublicKeyCredentialRequest(
                    options);
            currentCancellationSignal = new CancellationSignal();
            credentialManager.createCredentialAsync(activity, createPublicKeyCredentialRequest,
                    currentCancellationSignal, mainExecutor,
                    new CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException>() {

                        @Override
                        public void onResult(CreateCredentialResponse res) {
                            String resp = res.getData()
                                    .getString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON");
                            try {
                                JSONObject json = new JSONObject(resp);
                                JSONObject response = json.getJSONObject("response");

                                // Note: The "transports" field can be optional in the authenticator response.
                                // While the WebAuthn spec
                                // (https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-gettransports)
                                // does not strictly specify that "transports" must be omitted, we have observed
                                // several cases
                                // where authenticators do not return it.
                                List<String> typedTransports = new ArrayList<>();
                                JSONArray transports = response.optJSONArray("transports");
                                if (transports != null) {
                                    for (int i = 0; i < transports.length(); i++) {
                                        typedTransports.add(transports.getString(i));
                                    }
                                } else {
                                    typedTransports.add("");
                                }

                                deliverRegisterSuccess(new Messages.RegisterResponse.Builder()
                                        .setId(json.getString("id"))
                                        .setRawId(json.getString("rawId"))
                                        .setClientDataJSON(response.getString("clientDataJSON"))
                                        .setAttestationObject(response.getString("attestationObject"))
                                        .setTransports(typedTransports)
                                        .build());
                            } catch (JSONException e) {
                                Log.e(TAG, "Error parsing response: " + resp, e);
                                deliverRegisterError(e);
                            }
                        }

                        @Override
                        public void onError(CreateCredentialException e) {
                            Exception platformException = e;
                            if (Objects.equals(e.getMessage(), "Unable to create key during registration")) {
                                // currently, Android throws this error when users skip the fingerPrint
                                // animation => we interpret this as a cancellation for now
                                platformException = new Messages.FlutterError("cancelled", e.getMessage(), "");
                            } else if (e instanceof CreateCredentialCancellationException) {
                                platformException = new Messages.FlutterError("cancelled", e.getMessage(), "");
                            } else if (e instanceof CreatePublicKeyCredentialDomException) {
                                if (Objects.equals(e.getMessage(), "User is unable to create passkeys.")) {
                                    platformException = new Messages.FlutterError("android-missing-google-sign-in",
                                            e.getMessage(), MISSING_GOOGLE_SIGN_IN_ERROR);
                                } else if (Objects.equals(e.getMessage(), "Unable to get sync account.")) {
                                    platformException = new Messages.FlutterError("android-sync-account-not-available",
                                            e.getMessage(), SYNC_ACCOUNT_NOT_AVAILABLE_ERROR);
                                } else if (Objects.equals(e.getMessage(),
                                        "One of the excluded credentials exists on the local device")) {
                                    platformException = new Messages.FlutterError("exclude-credentials-match",
                                            e.getMessage(), EXCLUDE_CREDENTIALS_MATCH_ERROR);
                                } else if (Objects.equals(e.getMessage(), "[15] Flow has timed out.")) {
                                    platformException = new Messages.FlutterError("android-timeout", e.getMessage(),
                                            TIMEOUT_ERROR);
                                } else {
                                    platformException = new Messages.FlutterError("android-unhandled: " + e.getType(),
                                            e.getMessage(), e.getErrorMessage());
                                }
                            } else if (e instanceof CreateCredentialNoCreateOptionException) {
                                platformException = new Messages.FlutterError("android-no-create-option",
                                        e.getMessage(), MISSING_CREATION_OPTIONS);
                            } else {
                                platformException = new Messages.FlutterError("android-unhandled" + e.getType(),
                                        e.getMessage(), e.getErrorMessage());
                            }

                            deliverRegisterError(platformException);
                        }
                    });
        } catch (JSONException e) {
            Log.e(TAG, "Error creating JSON", e);
            deliverRegisterError(e);
        }
    }

    @Override
    public void authenticate(@NonNull String relyingPartyId, @NonNull String challenge, @Nullable Long timeout,
            @Nullable String userVerification, @Nullable List<Messages.AllowCredential> allowCredentials,
            @Nullable Boolean preferImmediatelyAvailableCredentials,
            @NonNull Messages.Result<Messages.AuthenticateResponse> result) {
        if (android.os.Build.VERSION.SDK_INT < 28) {
            result.error(new Messages.FlutterError("android-passkey-unsupported",
                    "Passkeys are only supported on Android API 28 and above.", null));
            return;
        }

        pendingAuthResult = result;
        authResultDelivered = false;

        List<AllowCredentialType> allowCredentialsType = new ArrayList<>();
        if (allowCredentials != null) {
            allowCredentialsType = allowCredentials.stream()
                    .map(c -> new AllowCredentialType(c.getType(), c.getId(), c.getTransports()))
                    .collect(Collectors.toList());
        }
        GetCredentialOptions getCredentialOptions = new GetCredentialOptions(challenge, timeout, relyingPartyId,
                allowCredentialsType, userVerification);
        Log.d(TAG, "[1] authenticate start: timeout=" + timeout
                + ", allowCredentials=" + allowCredentialsType.size()
                + ", userVerification=" + userVerification);
        try {
            String options = getCredentialOptions.toJSON().toString();

            Activity activity = plugin.requireActivity();

            CredentialManager credentialManager = CredentialManager.create(activity);

            GetPublicKeyCredentialOption getPublicKeyCredentialOption = new GetPublicKeyCredentialOption(options);

            GetCredentialRequest.Builder builder = new GetCredentialRequest.Builder()
                    .addCredentialOption(getPublicKeyCredentialOption);

            if (preferImmediatelyAvailableCredentials != null) {
                builder.setPreferImmediatelyAvailableCredentials(preferImmediatelyAvailableCredentials);
            }

            GetCredentialRequest getCredRequest = builder.build();
            currentCancellationSignal = new CancellationSignal();
            Log.d(TAG, "[2] getCredentialAsync called (CancellationSignal created)");

            if (timeout != null) {
                final long effectiveTimeout = 60000L; // TODO: remove after testing (shorten to 1 min)
                cancelTimeoutTimer();
                timeoutRunnable = () -> {
                    Log.d(TAG, "[T] Android-side timeout fired (timeout=" + effectiveTimeout + "ms)");
                    if (currentCancellationSignal != null) {
                        currentCancellationSignal.cancel();
                        currentCancellationSignal = null;
                        Log.d(TAG, "[T] CancellationSignal.cancel() called");
                    }
                    timeoutRunnable = null;
                    // GMS CABLE does not call onError after cancel(); deliver the timeout
                    // error directly so Flutter receives it and can show the appropriate UI.
                    Log.d(TAG, "[T] delivering android-timeout error directly to Flutter");
                    deliverAuthError(new Messages.FlutterError("android-timeout",
                            "Passkey operation timed out", TIMEOUT_ERROR));
                };
                timeoutHandler.postDelayed(timeoutRunnable, effectiveTimeout);
                Log.d(TAG, "[2] Android-side timeout timer set: " + effectiveTimeout + "ms");
            }

            credentialManager.getCredentialAsync(activity, getCredRequest, currentCancellationSignal, mainExecutor,
                    new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                        @Override
                        public void onResult(GetCredentialResponse res) {
                            cancelTimeoutTimer();
                            Log.d(TAG, "[3] onResult: credential type=" + res.getCredential().getClass().getSimpleName());
                            Credential credential = res.getCredential();
                            if (credential instanceof PublicKeyCredential) {
                                String responseJson = ((PublicKeyCredential) credential)
                                        .getAuthenticationResponseJson();
                                try {
                                    final JSONObject json = new JSONObject(responseJson);
                                    final JSONObject response = json.getJSONObject("response");

                                    final String id = json.getString("id");
                                    final String rawId = json.getString("rawId");

                                    final String clientDataJSON = response.getString("clientDataJSON");
                                    // userHandle is optional because some authenticators may return it as a null
                                    // (exp: cross-platform QR between two android devices)
                                    final String userHandle = response.optString("userHandle");
                                    final String signature = response.getString("signature");
                                    final String authenticatorData = response.getString("authenticatorData");

                                    final Messages.AuthenticateResponse msg = new Messages.AuthenticateResponse.Builder()
                                            .setId(id).setRawId(rawId).setClientDataJSON(clientDataJSON)
                                            .setAuthenticatorData(authenticatorData).setSignature(signature)
                                            .setUserHandle(userHandle).build();

                                    Log.d(TAG, "[3] onResult: success, id=" + id);
                                    deliverAuthSuccess(msg);
                                } catch (JSONException e) {
                                    Log.e(TAG, "[3] onResult: JSON parse error", e);
                                    deliverAuthError(e);
                                }
                            } else {
                                Log.e(TAG, "[3] onResult: unexpected credential type=" + credential.getClass().getName());
                                deliverAuthError(new Exception("Credential is of type " + credential.getClass().getName()
                                        + ", but should be of type PublicKeyCredential"));
                            }
                        }

                        @Override
                        public void onError(GetCredentialException e) {
                            cancelTimeoutTimer();
                            Log.e(TAG, "[3] onError: type=" + e.getClass().getSimpleName()
                                    + ", message=" + e.getMessage());
                            Exception platformException = e;

                            // currently, Android throws this error when users skip the fingerPrint
                            // animation => we interpret this as a cancellation for now
                            if (Objects.equals(e.getMessage(),
                                    "None of the allowed credentials can be authenticated")) {
                                platformException = new Messages.FlutterError("cancelled", e.getMessage(), "");
                            } else if (e instanceof GetCredentialCancellationException) {
                                platformException = new Messages.FlutterError("cancelled", e.getMessage(), "");
                            } else if (e instanceof NoCredentialException) {
                                platformException = new Messages.FlutterError("android-no-credential", e.getMessage(),
                                        "");
                            } else if (e instanceof GetPublicKeyCredentialDomException) {
                                if (Objects.equals(e.getMessage(), "Failed to decrypt credential.")) {
                                    platformException = new Messages.FlutterError("android-sync-account-not-available",
                                            e.getMessage(), SYNC_ACCOUNT_NOT_AVAILABLE_ERROR);
                                } else if (Objects.equals(e.getMessage(), "[15] Flow has timed out.")) {
                                    platformException = new Messages.FlutterError("android-timeout", e.getMessage(),
                                            TIMEOUT_ERROR);
                                } else {
                                    platformException = new Messages.FlutterError("android-unhandled: " + e.getType(),
                                            e.getMessage(), e.getErrorMessage());
                                }
                            } else {
                                platformException = new Messages.FlutterError("android-unhandled: " + e.getType(),
                                        e.getMessage(), e.getErrorMessage());
                            }

                            deliverAuthError(platformException);
                        }
                    });
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void cancelCurrentAuthenticatorOperation(@NonNull Messages.Result<Void> result) {
        Log.d(TAG, "[C] cancelCurrentAuthenticatorOperation: signal="
                + (currentCancellationSignal != null ? "exists" : "null"));
        cancelTimeoutTimer();
        if (currentCancellationSignal != null) {
            currentCancellationSignal.cancel();
            currentCancellationSignal = null;
            Log.d(TAG, "[C] CancellationSignal.cancel() called");
        }
        deliverAuthError(new Messages.FlutterError("cancelled", "Passkey operation cancelled", ""));
        deliverRegisterError(new Messages.FlutterError("cancelled", "Passkey operation cancelled", ""));
        result.success(null);
    }

    // Called by FlutterPasskeysPlugin when the app transitions to background (onStop).
    // Mirrors iOS ASAuthorizationController behaviour: cancel any pending credential
    // operation so the Dart side receives an error and can show the appropriate UI
    // when the user returns to the app.
    public void cancelOnBackground() {
        Log.d(TAG, "[P] app went to background, cancelling pending operation");
        cancelTimeoutTimer();
        if (currentCancellationSignal != null) {
            currentCancellationSignal.cancel();
            currentCancellationSignal = null;
            Log.d(TAG, "[P] CancellationSignal cancelled");
        }
        // GMS CABLE does not call onError after cancel(); deliver the error directly.
        Log.d(TAG, "[P] delivering cancelled error directly to Flutter");
        deliverAuthError(new Messages.FlutterError("cancelled",
                "Passkey operation cancelled: app went to background", ""));
        deliverRegisterError(new Messages.FlutterError("cancelled",
                "Passkey operation cancelled: app went to background", ""));
    }

    private void cancelTimeoutTimer() {
        if (timeoutRunnable != null) {
            timeoutHandler.removeCallbacks(timeoutRunnable);
            timeoutRunnable = null;
            Log.d(TAG, "[T] timeout timer cancelled");
        }
    }

    private void deliverAuthSuccess(Messages.AuthenticateResponse msg) {
        if (authResultDelivered || pendingAuthResult == null) return;
        authResultDelivered = true;
        Messages.Result<Messages.AuthenticateResponse> r = pendingAuthResult;
        pendingAuthResult = null;
        r.success(msg);
    }

    private void deliverAuthError(Exception e) {
        if (authResultDelivered || pendingAuthResult == null) return;
        authResultDelivered = true;
        Messages.Result<Messages.AuthenticateResponse> r = pendingAuthResult;
        pendingAuthResult = null;
        r.error(e);
    }

    private void deliverRegisterSuccess(Messages.RegisterResponse msg) {
        if (registerResultDelivered || pendingRegisterResult == null) return;
        registerResultDelivered = true;
        Messages.Result<Messages.RegisterResponse> r = pendingRegisterResult;
        pendingRegisterResult = null;
        r.success(msg);
    }

    private void deliverRegisterError(Exception e) {
        if (registerResultDelivered || pendingRegisterResult == null) return;
        registerResultDelivered = true;
        Messages.Result<Messages.RegisterResponse> r = pendingRegisterResult;
        pendingRegisterResult = null;
        r.error(e);
    }
}

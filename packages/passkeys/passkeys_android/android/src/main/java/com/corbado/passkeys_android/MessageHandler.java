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
import java.util.stream.Collectors;

public class MessageHandler implements Messages.PasskeysApi {

    private static final String TAG = "MessageHandler";
    private static final String SYNC_ACCOUNT_NOT_AVAILABLE_ERROR = "Sync account could not be accessed. If you are running on an emulator, please restart that device (select 'Could boot now').";
    private static final String MISSING_GOOGLE_SIGN_IN_ERROR = "Please sign in with a Google account first to create a new passkey.";
    private static final String EXCLUDE_CREDENTIALS_MATCH_ERROR = "You can not create a credential on this device because one of the excluded credentials exists on the local device.";
    private static final String MISSING_CREATION_OPTIONS = "Please make sure you enable a passwords or passkeys provider in your device settings.";
    private static final String TIMEOUT_ERROR = "Passkey operation timed out, please try again";

    private final FlutterPasskeysPlugin plugin;

    private CancellationSignal currentCancellationSignal;
    private final Handler timeoutHandler = new Handler(Looper.getMainLooper());
    private Runnable timeoutRunnable;

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
                    currentCancellationSignal, Runnable::run,
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

                                result.success(new Messages.RegisterResponse.Builder()
                                        .setId(json.getString("id"))
                                        .setRawId(json.getString("rawId"))
                                        .setClientDataJSON(response.getString("clientDataJSON"))
                                        .setAttestationObject(response.getString("attestationObject"))
                                        .setTransports(typedTransports)
                                        .build());
                            } catch (JSONException e) {
                                Log.e(TAG, "Error parsing response: " + resp, e);
                                result.error(e);
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

                            result.error(platformException);
                        }
                    });
        } catch (JSONException e) {
            Log.e(TAG, "Error creating JSON", e);
            result.error(e);
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

            // Android-side timeout: dismiss the CredentialManager System UI when the
            // WebAuthn timeout elapses. CancellationSignal.cancel() alone does NOT
            // dismiss the GMS "connecting" overlay during a BLE-waiting CABLE flow
            // (confirmed: onError never fires after cancel() in that state).
            // Recreating the Activity forces the GMS overlay to detach and close.
            if (timeout != null) {
                final long effectiveTimeout = 60000L; // TODO: remove after testing (shorten to 1 min)
                final GetCredentialRequest finalGetCredRequest = getCredRequest;
                cancelTimeoutTimer();
                timeoutRunnable = () -> {
                    Log.d(TAG, "[T] Android-side timeout fired (timeout=" + effectiveTimeout + "ms)");
                    // Step 1: cancel the existing signal (may not dismiss GMS CABLE UI)
                    if (currentCancellationSignal != null) {
                        currentCancellationSignal.cancel();
                        currentCancellationSignal = null;
                        Log.d(TAG, "[T] CancellationSignal.cancel() called");
                    }
                    timeoutRunnable = null;
                    // Step 2: issue a second getCredentialAsync with preferImmediatelyAvailableCredentials=true
                    // GMS typically allows only one concurrent operation: receiving a new request
                    // may force it to cancel the previous CABLE session and dismiss the QR overlay.
                    Log.d(TAG, "[T] issuing second getCredentialAsync to force GMS session reset");
                    CancellationSignal dummySignal = new CancellationSignal();
                    GetCredentialRequest forceCancelRequest = new GetCredentialRequest.Builder()
                            .addCredentialOption(new GetPublicKeyCredentialOption(
                                    finalGetCredRequest.getCredentialOptions().get(0)
                                            instanceof GetPublicKeyCredentialOption
                                    ? ((GetPublicKeyCredentialOption) finalGetCredRequest
                                            .getCredentialOptions().get(0)).getRequestJson()
                                    : "{}"))
                            .setPreferImmediatelyAvailableCredentials(true)
                            .build();
                    CredentialManager cm = CredentialManager.create(activity);
                    cm.getCredentialAsync(activity, forceCancelRequest, dummySignal, Runnable::run,
                            new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                                @Override
                                public void onResult(GetCredentialResponse res) {
                                    Log.d(TAG, "[T2] second call onResult (ignored)");
                                    dummySignal.cancel();
                                }
                                @Override
                                public void onError(GetCredentialException e) {
                                    Log.d(TAG, "[T2] second call onError: " + e.getClass().getSimpleName()
                                            + " / " + e.getMessage());
                                }
                            });
                    // Cancel the second request immediately after starting it
                    dummySignal.cancel();
                    Log.d(TAG, "[T] second call dummySignal cancelled");
                };
                timeoutHandler.postDelayed(timeoutRunnable, effectiveTimeout);
                Log.d(TAG, "[2] Android-side timeout timer set: " + effectiveTimeout + "ms");
            }

            credentialManager.getCredentialAsync(activity, getCredRequest, currentCancellationSignal, Runnable::run,
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
                                    result.success(msg);
                                } catch (JSONException e) {
                                    Log.e(TAG, "[3] onResult: JSON parse error", e);
                                    result.error(e);
                                }
                            } else {
                                Log.e(TAG, "[3] onResult: unexpected credential type=" + credential.getClass().getName());
                                result.error(new Exception("Credential is of type " + credential.getClass().getName()
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

                            result.error(platformException);
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

        result.success(null);
    }

    private void cancelTimeoutTimer() {
        if (timeoutRunnable != null) {
            timeoutHandler.removeCallbacks(timeoutRunnable);
            timeoutRunnable = null;
            Log.d(TAG, "[T] timeout timer cancelled");
        }
    }
}

package com.corbado.passkeys_android;

import android.app.Activity;
import android.app.Application;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.flutter.embedding.android.FlutterActivity;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.embedding.engine.plugins.activity.ActivityAware;
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodChannel;

public class FlutterPasskeysPlugin extends FlutterActivity implements FlutterPlugin, ActivityAware {
    private static final String TAG = "FlutterPasskeysPlugin";
    private BinaryMessenger binaryMessenger;
    private Activity activity;
    private MessageHandler messageHandler;

    // Cancel any pending passkey operation when the app goes to background.
    // This replicates the behaviour of iOS's ASAuthorizationController, which
    // automatically errors out when the app loses foreground focus.
    private final Application.ActivityLifecycleCallbacks lifecycleCallbacks =
            new Application.ActivityLifecycleCallbacks() {
                @Override
                public void onActivityStopped(@NonNull Activity a) {
                    if (a == activity && messageHandler != null) {
                        messageHandler.cancelOnBackground();
                    }
                }
                @Override public void onActivityCreated(@NonNull Activity a, @Nullable Bundle b) {}
                @Override public void onActivityStarted(@NonNull Activity a) {}
                @Override public void onActivityResumed(@NonNull Activity a) {}
                @Override public void onActivityPaused(@NonNull Activity a) {}
                @Override public void onActivitySaveInstanceState(@NonNull Activity a, @NonNull Bundle b) {}
                @Override public void onActivityDestroyed(@NonNull Activity a) {}
            };

    public FlutterPasskeysPlugin() {
    }

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding binding) {
        binaryMessenger = binding.getBinaryMessenger();
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        binaryMessenger = null;
    }

    @Override
    public void onAttachedToActivity(@NonNull ActivityPluginBinding binding) {
        activity = binding.getActivity();
        messageHandler = new MessageHandler(this);
        Messages.PasskeysApi.setup(binaryMessenger, messageHandler);
        activity.getApplication().registerActivityLifecycleCallbacks(lifecycleCallbacks);
    }

    public Activity requireActivity() {
        if (activity == null) throw new IllegalStateException("Activity not found");
        return activity;
    }

    @Override
    public void onDetachedFromActivityForConfigChanges() {
        unregisterLifecycleCallbacks();
        activity = null;
    }

    @Override
    public void onReattachedToActivityForConfigChanges(@NonNull ActivityPluginBinding binding) {
        activity = binding.getActivity();
        activity.getApplication().registerActivityLifecycleCallbacks(lifecycleCallbacks);
    }

    @Override
    public void onDetachedFromActivity() {
        unregisterLifecycleCallbacks();
        activity = null;
    }

    private void unregisterLifecycleCallbacks() {
        if (activity != null) {
            activity.getApplication().unregisterActivityLifecycleCallbacks(lifecycleCallbacks);
        }
    }
}
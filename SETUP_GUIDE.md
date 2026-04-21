# Kryonix Android App — Complete Setup Guide

---

## What's included

This is a **full native Android app** written in Kotlin that connects to your existing
Flask backend via REST API + Socket.IO. It includes:

- Login / Register / Email 2FA
- Real-time messaging (direct + group) via Socket.IO
- WebRTC video & audio calls
- Push notifications even when app is closed (FCM)
- Friends management
- Settings (profile picture, password, theme)

---

## Step 1 — Install Android Studio

1. Download **Android Studio** (free) from https://developer.android.com/studio
2. Install it (Windows/Mac/Linux all supported).
3. On first launch let it download the **Android SDK** automatically.

---

## Step 2 — Open the project

1. Launch Android Studio.
2. Click **"Open"** (not "New Project").
3. Navigate to the `KryonixApp` folder you extracted and click **OK**.
4. Wait for Gradle to sync (bottom status bar). First sync downloads ~500 MB of libraries. This takes a few minutes.

---

## Step 3 — Set your server URL  ⚠️ REQUIRED

Open `app/build.gradle` and replace the placeholder URLs on these two lines:

```gradle
buildConfigField "String", "BASE_URL",   '"https://your-kryonix-domain.com"'
buildConfigField "String", "SOCKET_URL", '"https://your-kryonix-domain.com"'
```

For example if your domain is `chat.mysite.com`:
```gradle
buildConfigField "String", "BASE_URL",   '"https://chat.mysite.com"'
buildConfigField "String", "SOCKET_URL", '"https://chat.mysite.com"'
```

After editing, click **"Sync Now"** in the yellow bar at the top.

> **Local dev on the same network?**
> Use your PC's local IP, e.g. `"http://192.168.1.50:5001"`, and change
> `network_security_config.xml` to allow cleartext for that IP (example is already
> commented in the file).

---

## Step 4 — Set up Firebase (for push notifications)  ⚠️ REQUIRED

> If you skip this, the app won't compile because the placeholder
> `google-services.json` is invalid.

### 4a. Create a Firebase project
1. Go to https://console.firebase.google.com
2. Click **"Add project"** → name it `Kryonix` → click through the wizard.

### 4b. Add an Android app to the project
1. In your Firebase project, click the **Android icon** (or **"Add app"**).
2. Enter package name exactly: `com.kryonix.app`
3. Enter a nickname (e.g. "Kryonix Android").
4. Click **"Register app"**.

### 4c. Download google-services.json
1. On the next page, click **"Download google-services.json"**.
2. **Replace** the placeholder file at `app/google-services.json` with this downloaded file.

### 4d. Enable Cloud Messaging
1. In Firebase Console → your project → **"Cloud Messaging"** tab.
2. It should already be enabled. Note your **Server Key** for Step 6.

---

## Step 5 — Add API endpoints to your Flask backend  ⚠️ REQUIRED

The included file `flask_api_endpoints.py` contains all the new JSON routes the
Android app uses. Your existing Flask app only has HTML form routes — you need
to add the JSON counterparts.

### 5a. Add the fcm_token column
In your existing `app.py`, find the `UserModel` class and add this field:

```python
fcm_token = db.Column(db.String(512), nullable=True)
```

### 5b. Copy the API routes
Open `flask_api_endpoints.py` and copy everything **below** the dashed separator
line into the bottom of your `app.py` (before the `if __name__ == '__main__':` block).

### 5c. Install firebase-admin
On your server, run:
```bash
pip install firebase-admin
```

### 5d. Add Firebase service account
1. Firebase Console → Project Settings → **Service Accounts** tab.
2. Click **"Generate new private key"** → download the JSON file.
3. Save it as `firebase_service_account.json` **in the same directory as `app.py`**.

### 5e. Hook FCM into your message handler
In `app.py`, find the `handle_send_message` socket handler.
After the line `emit('message', message_data, room=room)`, add:

```python
# Send FCM push to recipient if they have a token
if not room.startswith('group_'):
    parts = room.split('-')
    recipient = parts[1] if parts[0] == username else parts[0]
    rm = get_user_model(recipient)
    if rm and rm.fcm_token:
        send_fcm_notification(
            rm.fcm_token,
            title=username,
            body=strip_tags(msg)[:100],
            data={
                'type': 'message', 'sender': username,
                'content': strip_tags(msg)[:100],
                'room_id': room, 'room_type': 'direct', 'room_name': username
            }
        )
```

---

## Step 6 — Build and run the app

### Option A — Run on your physical phone (recommended)
1. On your Android phone: **Settings → Developer Options → USB Debugging** → Enable.
   (To enable Developer Options: Settings → About Phone → tap "Build number" 7 times.)
2. Connect phone to PC via USB.
3. In Android Studio, select your phone from the device dropdown (top toolbar).
4. Click the green **▶ Run** button (or press `Shift+F10`).
5. Android Studio builds and installs the app directly on your phone.

### Option B — Run on an emulator
1. In Android Studio: **Tools → Device Manager → Create Device**.
2. Choose "Pixel 6" → Next → download "API 34" system image → Finish.
3. Start the emulator, then click ▶ Run.

### Option C — Build a release APK to share
1. **Build → Generate Signed Bundle / APK**.
2. Choose **APK**.
3. Create a keystore (follow the wizard — save the keystore file and passwords somewhere safe).
4. Select **release** build variant → Finish.
5. Your APK will be at `app/release/app-release.apk`.
6. Transfer this APK to any Android phone and install it
   (you may need to enable "Install from unknown sources" in phone settings).

---

## Step 7 — Verify everything works

1. Start your Flask backend server.
2. Install the app.
3. Register a new account — you should receive a verification email.
4. Log in — you should receive the 2FA code email.
5. Add a friend and start chatting.
6. Kill the app entirely (swipe away from recents) and ask the friend to send you a message — you should receive a push notification.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Gradle sync fails with "Could not resolve..." | Check your internet connection. Try File → Invalidate Caches → Restart. |
| `google-services.json` error | Make sure you replaced the placeholder with your real file from Firebase. |
| App connects but login fails | Double-check `BASE_URL` in `build.gradle` and make sure Flask is running and reachable from the phone's network. |
| No push notifications | Check that `firebase_service_account.json` is on the server and `fcm_token` column exists in the DB. |
| WebRTC call audio/video not working | Make sure CAMERA and RECORD_AUDIO permissions were granted on the phone. |
| "Cleartext HTTP traffic not permitted" | Your server must use HTTPS, OR add your IP to `network_security_config.xml` as shown in the comments. |

---

## File structure summary

```
KryonixApp/
├── app/
│   ├── build.gradle                    ← Edit BASE_URL here
│   ├── google-services.json            ← Replace with real Firebase file
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/com/kryonix/app/
│   │   │   ├── api/
│   │   │   │   ├── KryonixApi.kt       ← Retrofit endpoints
│   │   │   │   ├── NetworkClient.kt    ← HTTP client + cookie jar
│   │   │   │   └── SocketManager.kt    ← Socket.IO client
│   │   │   ├── models/Models.kt        ← All data classes
│   │   │   ├── services/
│   │   │   │   ├── KryonixFirebaseService.kt  ← FCM push handler
│   │   │   │   └── SocketService.kt    ← Background socket service
│   │   │   ├── ui/
│   │   │   │   ├── auth/               ← Login, Register, 2FA screens
│   │   │   │   ├── chat/               ← Contacts list, Chat screen
│   │   │   │   ├── calls/              ← WebRTC call screen
│   │   │   │   ├── friends/            ← Friends management
│   │   │   │   └── settings/           ← Settings screen
│   │   │   ├── utils/SessionManager.kt ← Persistent login state
│   │   │   └── KryonixApplication.kt
│   │   └── res/                        ← All layouts, drawables, etc.
├── flask_api_endpoints.py              ← Add these routes to your app.py
└── SETUP_GUIDE.md                      ← You are here
```

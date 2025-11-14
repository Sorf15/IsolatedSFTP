# IsolatedSFTP

**IsolatedSFTP** — A secure, container-style SFTP server written in Java 8.

Each regular user has an isolated virtual filesystem; a single **super-admin** (created at startup) can moderate **all** users, while **regular admins (moderators)** are limited to monitoring/moderating **exactly one** regular user.

This project uses Gradle (tested with Gradle 7.1.1).

---

## Build

Use the Gradle wrapper (recommended). If the wrapper is not present, create it with `gradle wrapper --gradle-version 7.1.1`.

Build the fat jar (task provided in `build.gradle`):

Unix / macOS:
```bash
./gradlew clean fatJar
````

Windows (PowerShell / CMD):

```powershell
gradlew.bat clean fatJar
```

After a successful run, the fat jar will be in:

```
build/libs/all-in-one-jar-<version>.jar
```

(e.g. `build/libs/all-in-one-jar-1.0-SNAPSHOT.jar`)

---

## Run

The program expects **4 CLI arguments** on startup:

```
java -jar build/libs/all-in-one-jar-<version>.jar <path_to_the_work_folder> <port> <super_admin_username> <super_admin_pass>
```

Example:

```bash
java -jar build/libs/all-in-one-jar-1.0-SNAPSHOT.jar /srv/isolated-sftp 2222 admin StrongAdminPass123
```

If the program is started without 4 arguments it will warn and prompt to continue with defaults or exit.

> **Important:** the super-admin credentials are set at startup and cannot be changed later by design. Choose a strong password at startup.

---

## Admin model

* **Super-admin**
    * Created at server startup.
    * Has global moderation rights — can inspect and moderate *all* regular users’ sessions and files.
    * Credentials are immutable during runtime.

* **Regular admin (moderator)**

    * Created via admin CLI (e.g. `addAdm <parent> <username> <password> <duration>`).
    * Each regular admin is linked to **one** regular user (the “parent” user).
    * Can see and moderate only the assigned user's virtual filesystem and session.

* **Regular users**

    * Have private, per-user isolated virtual filesystems.
    * Read-only permissions are enforced server-side.

---

## Admin CLI (interactive)

After the server starts an admin console is available. Key commands can be view using:
```
help
?
```

---

## User lifetime model

Users may be created with a limited lifetime (e.g. `24h`, `2d`, `1w4d15h`). When the lifetime expires the user is **suspended** (not deleted): the account cannot connect but its files remain intact. Users can be `append` (unsuspend or extend), `delUser` (delete permanently). Use `inf` for accounts that never expire.


/*
 * This file is part of ViaProxy - https://github.com/RaphiMC/ViaProxy
 * Copyright (C) 2021-2026 RK_01/RaphiMC and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.raphimc.viaproxy.tasks;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.vdurmont.semver4j.Semver;
import net.raphimc.viaproxy.ViaProxy;

import net.raphimc.viaproxy.util.JarUtil;
import net.raphimc.viaproxy.util.logging.Logger;

import javax.swing.*;
import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import static net.raphimc.viaproxy.ViaProxy.VERSION;

public class UpdateCheckTask implements Runnable {

    private final boolean hasUI;

    public UpdateCheckTask(final boolean hasUI) {
        this.hasUI = hasUI;
    }

    @Override
    @SuppressWarnings("UnreachableCode")
    public void run() {
        if (VERSION.startsWith("$")) return; // Dev env check
        try {
            URL url = new URL("https://api.github.com/repos/RaphiMC/ViaProxy/releases/latest");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("User-Agent", "ViaProxy/" + VERSION);
            con.setConnectTimeout(5000);
            con.setReadTimeout(5000);

            InputStream in = con.getInputStream();
            byte[] bytes = new byte[1024];
            int read;
            StringBuilder builder = new StringBuilder();
            while ((read = in.read(bytes)) != -1) builder.append(new String(bytes, 0, read));
            con.disconnect();

            JsonObject object = JsonParser.parseString(builder.toString()).getAsJsonObject();
            String latestVersion = object.get("tag_name").getAsString().substring(1);
            boolean updateAvailable;
            try {
                Semver versionSemver = new Semver(VERSION);
                Semver latestVersionSemver = new Semver(latestVersion);
                updateAvailable = latestVersionSemver.isGreaterThan(versionSemver);
                if (versionSemver.isGreaterThan(latestVersionSemver)) Logger.LOGGER.warn("You are running a dev version of ViaProxy");
            } catch (Throwable t) {
                updateAvailable = !VERSION.equals(latestVersion);
            }
            if (updateAvailable) {
                Logger.LOGGER.warn("You are running an outdated version of ViaProxy! Latest version: " + latestVersion);
                if (this.hasUI && JarUtil.getJarFile().isPresent()) {
                    final boolean runsJava8 = System.getProperty("java.version").startsWith("1.8");
                    JsonArray assets = object.getAsJsonArray("assets");
                    boolean found = false;
                    for (JsonElement asset : assets) {
                        JsonObject assetObject = asset.getAsJsonObject();
                        if ((this.isMainViaProxyJar(object, assetObject) && !runsJava8) || this.isJava8ViaProxyJar(object, assetObject) && runsJava8) {
                            found = true;
                            break;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }




    private boolean isMainViaProxyJar(final JsonObject root, final JsonObject assetObject) {
        return assetObject.get("name").getAsString().equals(root.get("name").getAsString() + ".jar");
    }

    private boolean isJava8ViaProxyJar(final JsonObject root, final JsonObject assetObject) {
        return assetObject.get("name").getAsString().equals(root.get("name").getAsString() + "+java8.jar");
    }

}

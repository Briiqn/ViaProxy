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
package net.raphimc.viaproxy;

import io.netty.channel.Channel;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.util.ResourceLeakDetector;
import io.netty.util.concurrent.GlobalEventExecutor;
import io.netty.util.internal.PlatformDependent;
import net.lenni0451.classtransform.TransformerManager;
import net.lenni0451.classtransform.additionalclassprovider.GuavaClassPathProvider;
import net.lenni0451.classtransform.mixinstranslator.MixinsTranslator;
import net.lenni0451.classtransform.utils.loader.EnumLoaderPriority;
import net.lenni0451.classtransform.utils.loader.InjectionClassLoader;
import net.lenni0451.classtransform.utils.tree.IClassProvider;
import net.lenni0451.lambdaevents.LambdaManager;
import net.lenni0451.lambdaevents.generator.LambdaMetaFactoryGenerator;
import net.lenni0451.reflect.Agents;
import net.lenni0451.reflect.ClassLoaders;
import net.lenni0451.reflect.JavaBypass;
import net.lenni0451.reflect.Methods;
import net.raphimc.minecraftauth.MinecraftAuth;
import net.raphimc.minecraftauth.bedrock.BedrockAuthManager;
import net.raphimc.minecraftauth.msa.model.MsaCredentials;
import net.raphimc.minecraftauth.msa.model.MsaDeviceCode;
import net.raphimc.minecraftauth.msa.service.impl.CredentialsMsaAuthService;
import net.raphimc.minecraftauth.msa.service.impl.DeviceCodeMsaAuthService;
import net.raphimc.netminecraft.constants.MCPipeline;
import net.raphimc.netminecraft.netty.connection.NetServer;
import net.raphimc.viabedrock.api.BedrockProtocolVersion;
import net.raphimc.viabedrock.protocol.data.ProtocolConstants;
import net.raphimc.viaproxy.cli.ConsoleHandler;
import net.raphimc.viaproxy.plugins.PluginManager;
import net.raphimc.viaproxy.plugins.events.Client2ProxyHandlerCreationEvent;
import net.raphimc.viaproxy.plugins.events.ProxyStartEvent;
import net.raphimc.viaproxy.plugins.events.ProxyStopEvent;
import net.raphimc.viaproxy.plugins.events.ViaProxyLoadedEvent;
import net.raphimc.viaproxy.protocoltranslator.ProtocolTranslator;
import net.raphimc.viaproxy.protocoltranslator.viaproxy.ViaProxyConfig;
import net.raphimc.viaproxy.proxy.client2proxy.Client2ProxyChannelInitializer;
import net.raphimc.viaproxy.proxy.client2proxy.Client2ProxyHandler;
import net.raphimc.viaproxy.proxy.session.ProxyConnection;
import net.raphimc.viaproxy.saves.SaveManager;
import net.raphimc.viaproxy.saves.impl.accounts.BedrockAccount;
import net.raphimc.viaproxy.tasks.SystemRequirementsCheck;
import net.raphimc.viaproxy.tasks.UpdateCheckTask;
import net.raphimc.viaproxy.util.AddressUtil;
import net.raphimc.viaproxy.util.ClassLoaderPriorityUtil;
import net.raphimc.viaproxy.util.JarUtil;
import net.raphimc.viaproxy.util.logging.Logger;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public class ViaProxy {

    public static final String VERSION = "${version}";
    public static final String IMPL_VERSION = "git-ViaProxy-${version}:${commit_hash}";

    public static final LambdaManager EVENT_MANAGER = LambdaManager.threadSafe(new LambdaMetaFactoryGenerator(JavaBypass.TRUSTED_LOOKUP));
    private static /*final*/ File CWD;
    private static /*final*/ PluginManager PLUGIN_MANAGER;
    private static /*final*/ SaveManager SAVE_MANAGER;
    private static /*final*/ ViaProxyConfig CONFIG;
    private static /*final*/ ChannelGroup CLIENT_CHANNELS;

    private static Instrumentation instrumentation;
    private static NetServer currentProxyServer;

    public static void agentmain(final String args, final Instrumentation instrumentation) {
        ViaProxy.instrumentation = instrumentation;
    }

    public static void main(String[] args) throws Throwable {
        final IClassProvider classProvider = new GuavaClassPathProvider();
        final TransformerManager transformerManager = new TransformerManager(classProvider);
        transformerManager.addTransformerPreprocessor(new MixinsTranslator());
        transformerManager.addTransformer("net.raphimc.viaproxy.injection.mixins.**");
        if (instrumentation != null) {
            transformerManager.hookInstrumentation(instrumentation);
            injectedMain("Launcher Agent", args);
            return;
        }
        try {
            transformerManager.hookInstrumentation(Agents.getInstrumentation());
        } catch (Throwable t) {
            final InjectionClassLoader injectionClassLoader = new InjectionClassLoader(transformerManager, ClassLoaders.getSystemClassPath());
            injectionClassLoader.setPriority(EnumLoaderPriority.PARENT_FIRST);
            Thread.currentThread().setContextClassLoader(injectionClassLoader);
            Methods.invoke(null, Methods.getDeclaredMethod(injectionClassLoader.loadClass(ViaProxy.class.getName()), "injectedMain", String.class, String[].class), "Injection ClassLoader", args);
            return;
        }
        injectedMain("Runtime Agent", args);
    }

    public static void injectedMain(final String injectionMethod, final String[] args) throws InterruptedException, IOException, InvocationTargetException {
        final List<File> potentialCwds = new ArrayList<>();
        if (System.getenv("VP_RUN_DIR") != null) {
            potentialCwds.add(new File(System.getenv("VP_RUN_DIR")));
        }
        potentialCwds.add(new File(System.getProperty("user.dir")));
        potentialCwds.add(new File("."));
        JarUtil.getJarFile().map(File::getParentFile).ifPresent(potentialCwds::add);

        final List<File> failedCwds = new ArrayList<>();
        for (File potentialCwd : potentialCwds) {
            if (potentialCwd.isDirectory()) {
                if (Files.isWritable(potentialCwd.toPath())) {
                    CWD = potentialCwd;
                    break;
                }
            }
            failedCwds.add(potentialCwd);
        }
        if (CWD == null) {
            for (File potentialCwd : potentialCwds) {
                if (potentialCwd.isDirectory()) {
                    try {
                        final Path testFile = new File(potentialCwd, "viaproxy_writable_test.txt").toPath();
                        Files.deleteIfExists(testFile);
                        Files.writeString(testFile, "This is just a test. This file can be deleted.");
                        Files.deleteIfExists(testFile);
                        CWD = potentialCwd;
                        break;
                    } catch (IOException ignored) {
                    }
                }
            }
        }
        if (CWD != null) {
            System.setProperty("user.dir", CWD.getAbsolutePath());
        } else {
            System.err.println("Could not find a suitable directory to use as working directory. Make sure that the current folder is writeable.");
            System.err.println("Attempted to use the following directories:");
            for (File failedCwd : failedCwds) {
                System.err.println("\t- " + failedCwd.getAbsolutePath());
            }
            System.exit(1);
        }

        Logger.setup();
        Logger.LOGGER.info("Initializing ViaProxy CLI v{} ({}) (Injected using {})...", VERSION, IMPL_VERSION, injectionMethod);
        Logger.LOGGER.info("Using java version: " + System.getProperty("java.vm.name") + " " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ") on " + System.getProperty("os.name"));
        Logger.LOGGER.info("Available memory (bytes): " + Runtime.getRuntime().maxMemory());
        Logger.LOGGER.info("Working directory: " + CWD.getAbsolutePath());
        if (!failedCwds.isEmpty()) {
            Logger.LOGGER.warn("Failed to use the following directories as working directory:");
            for (File failedCwd : failedCwds) {
                Logger.LOGGER.warn("\t- " + failedCwd.getAbsolutePath());
            }
        }
        if (System.getProperty("ignoreSystemRequirements") == null) {
            SystemRequirementsCheck.run(false);
        }

        ConsoleHandler.hookConsole();
        ViaProxy.loadNetty();
        ClassLoaderPriorityUtil.loadOverridingJars();

        PLUGIN_MANAGER = new PluginManager();
        ProtocolTranslator.init();
        SAVE_MANAGER = new SaveManager();

        final File viaProxyConfigFile;
        if (args.length == 2 && args[0].equals("config")) {
            final File absoluteConfigFile = new File(args[1]);
            if (absoluteConfigFile.isAbsolute()) {
                viaProxyConfigFile = absoluteConfigFile;
            } else {
                viaProxyConfigFile = new File(ViaProxy.getCwd(), args[1]);
            }
        } else {
            viaProxyConfigFile = new File(ViaProxy.getCwd(), "viaproxy.yml");
        }
        CONFIG = ViaProxyConfig.create(viaProxyConfigFile);

        CONFIG.setTargetVersion(BedrockProtocolVersion.bedrockLatest);
        CONFIG.setAuthMethod(ViaProxyConfig.AuthMethod.ACCOUNT);

        final File accountsFile = new File(ViaProxy.getCwd(), "accounts.txt");
        if (accountsFile.exists()) {
            new Thread(() -> {
                Logger.LOGGER.info("Loading accounts from background thread...");
                try {
                    final List<String> lines = Files.readAllLines(accountsFile.toPath());
                    int loaded = 0;
                    for (String line : lines) {
                        final String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            final String email = parts[0].trim();
                            final String password = parts[1].trim();

                            try {
                                Logger.LOGGER.info("Authenticating " + email + "...");
                                final BedrockAuthManager authManager = BedrockAuthManager.create(MinecraftAuth.createHttpClient(), ProtocolConstants.BEDROCK_VERSION_NAME)
                                        .login(CredentialsMsaAuthService::new, new MsaCredentials(email, password));

                                final BedrockAccount account = new BedrockAccount(authManager);

                                SAVE_MANAGER.accountsSave.addAccount(account);
                                Logger.LOGGER.info("Successfully loaded account: " + account.getName());
                                loaded++;
                            } catch (Throwable t) {
                                Logger.LOGGER.error("Failed to authenticate account: " + email, t);
                            }
                        }
                    }

                    if (loaded > 0) {
                        SAVE_MANAGER.save();
                        Logger.LOGGER.info("Loaded " + loaded + " accounts from accounts.txt");
                        Files.move(accountsFile.toPath(), new File(ViaProxy.getCwd(), "accounts.txt.loaded").toPath());
                    } else {
                        Logger.LOGGER.warn("No valid accounts processed from accounts.txt");
                    }
                } catch (IOException e) {
                    Logger.LOGGER.error("Failed to read accounts.txt", e);
                }
            }, "Account Loader").start();
        }

        if (System.getProperty("skipUpdateCheck") == null) {
            CompletableFuture.runAsync(new UpdateCheckTask(false));
        }
        EVENT_MANAGER.call(new ViaProxyLoadedEvent());
        Logger.LOGGER.info("ViaProxy started successfully!");
        ViaProxy.startProxy();

        Thread.sleep(Integer.MAX_VALUE);
    }

    public static void startProxy() {
        if (currentProxyServer != null) {
            throw new IllegalStateException("Proxy is already running");
        }
        try {
            Logger.LOGGER.info("Starting proxy server");

            currentProxyServer = new NetServer(new Client2ProxyChannelInitializer(() -> EVENT_MANAGER.call(new Client2ProxyHandlerCreationEvent(new Client2ProxyHandler(), false)).getHandler()));
            EVENT_MANAGER.call(new ProxyStartEvent());
            currentProxyServer.bind(new InetSocketAddress(0x1337), false);
        } catch (Throwable e) {
            currentProxyServer = null;
            throw e;
        }
    }

    public static void stopProxy() {
        if (currentProxyServer != null) {
            Logger.LOGGER.info("Stopping proxy server");
            EVENT_MANAGER.call(new ProxyStopEvent());

            currentProxyServer.getChannel().close();
            currentProxyServer = null;

            for (Channel channel : CLIENT_CHANNELS) {
                try {
                    ProxyConnection.fromChannel(channel).kickClient("§cViaProxy has been stopped");
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static void loadNetty() {
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.DISABLED);
        if (System.getProperty("io.netty.allocator.type") == null) {
            System.setProperty("io.netty.allocator.type", PlatformDependent.isAndroid() ? "unpooled" : "pooled");
        }
        MCPipeline.useOptimizedPipeline();
        CLIENT_CHANNELS = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    }

    public static File getCwd() {
        return CWD;
    }

    public static PluginManager getPluginManager() {
        return PLUGIN_MANAGER;
    }

    public static SaveManager getSaveManager() {
        return SAVE_MANAGER;
    }

    public static ViaProxyConfig getConfig() {
        return CONFIG;
    }

    public static ChannelGroup getConnectedClients() {
        return CLIENT_CHANNELS;
    }

    public static NetServer getCurrentProxyServer() {
        return currentProxyServer;
    }

}
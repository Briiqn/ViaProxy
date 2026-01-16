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
package net.raphimc.viaproxy.util;

import net.raphimc.viaproxy.ViaProxy;
import net.raphimc.viaproxy.saves.impl.accounts.Account;
import net.raphimc.viaproxy.saves.impl.accounts.MicrosoftAccount;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class AccountPool {

    private static final Set<UUID> activeAccounts = new HashSet<>();

    public static synchronized Account acquire() {
        for (Account account : ViaProxy.getSaveManager().accountsSave.getAccounts()) {
            if (account instanceof MicrosoftAccount) {
                if (!activeAccounts.contains(account.getUUID())) {
                    activeAccounts.add(account.getUUID());
                    return account;
                }
            }
        }
        return null;
    }

    public static synchronized void release(Account account) {
        if (account != null) {
            activeAccounts.remove(account.getUUID());
        }
    }
}
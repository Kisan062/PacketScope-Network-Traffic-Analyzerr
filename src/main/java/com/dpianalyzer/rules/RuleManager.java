package com.dpianalyzer.rules;

import com.dpianalyzer.model.AppType;

import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Manages blocking rules for the DPI engine.
 * Thread-safe — rules can be updated from the GUI while processing runs.
 *
 * Three rule types:
 *   1. IP block       — block all traffic from a specific source IP
 *   2. App block      — block an entire application (e.g., YouTube)
 *   3. Domain block   — block any SNI containing a keyword
 */
public class RuleManager {

    private final Set<String>  blockedIps     = new CopyOnWriteArraySet<>();
    private final Set<AppType> blockedApps    = new CopyOnWriteArraySet<>();
    private final Set<String>  blockedDomains = new CopyOnWriteArraySet<>();

    // ── IP Rules ──────────────────────────────────────────────────
    public void blockIp(String ip)   { blockedIps.add(ip.trim()); }
    public void unblockIp(String ip) { blockedIps.remove(ip.trim()); }
    public Set<String> getBlockedIps() { return Collections.unmodifiableSet(blockedIps); }

    // ── App Rules ─────────────────────────────────────────────────
    public void blockApp(AppType app)   { blockedApps.add(app); }
    public void unblockApp(AppType app) { blockedApps.remove(app); }
    public Set<AppType> getBlockedApps() { return Collections.unmodifiableSet(blockedApps); }

    // ── Domain Rules ──────────────────────────────────────────────
    public void blockDomain(String keyword)   { blockedDomains.add(keyword.toLowerCase().trim()); }
    public void unblockDomain(String keyword) { blockedDomains.remove(keyword.toLowerCase().trim()); }
    public Set<String> getBlockedDomains() { return Collections.unmodifiableSet(blockedDomains); }

    /**
     * Check if a flow should be blocked. Returns the reason, or null if allowed.
     */
    public String checkBlocked(String srcIp, AppType appType, String sni) {
        if (blockedIps.contains(srcIp)) {
            return "IP blocked: " + srcIp;
        }
        if (blockedApps.contains(appType)) {
            return "App blocked: " + appType.displayName;
        }
        if (sni != null && !sni.isBlank()) {
            String lower = sni.toLowerCase();
            for (String domain : blockedDomains) {
                if (lower.contains(domain)) {
                    return "Domain blocked: " + domain;
                }
            }
        }
        return null; // Not blocked
    }

    public boolean hasAnyRules() {
        return !blockedIps.isEmpty() || !blockedApps.isEmpty() || !blockedDomains.isEmpty();
    }

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
    }

    @Override
    public String toString() {
        return String.format("RuleManager[IPs=%d, Apps=%d, Domains=%d]",
                blockedIps.size(), blockedApps.size(), blockedDomains.size());
    }
}

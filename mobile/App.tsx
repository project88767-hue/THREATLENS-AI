import React, { useState } from "react";
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { mobileApi } from "./src/api/mobileClient";

interface ScanSummary {
  id: string;
  scanType: string;
  normalizedValue: string;
  riskScore: number;
  severity: string;
  verdict: string;
  summary: string;
}

export default function App() {
  const [token, setToken] = useState<string | null>(null);
  const [userName, setUserName] = useState("");
  const [email, setEmail] = useState("analyst@threatlens.demo");
  const [password, setPassword] = useState("Analyst@12345");
  const [tab, setTab] = useState<"dashboard" | "scan" | "incidents">("dashboard");

  const [kpis, setKpis] = useState<Record<string, number>>({});
  const [incidents, setIncidents] = useState<
    Array<{ id: string; code: string; title: string; severity: string; status: string }>
  >([]);
  const [scanMode, setScanMode] = useState<"url" | "ip" | "cve">("url");
  const [target, setTarget] = useState(
    "http://microsoft-verify-login.account-update.xyz/secure"
  );
  const [scanResult, setScanResult] = useState<ScanSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadSocOverview = async (jwt: string) => {
    const [dash, incRes] = await Promise.all([
      mobileApi<{ kpis: Record<string, number> }>("/api/dashboard/overview", jwt),
      mobileApi<{
        incidents: Array<{
          id: string;
          code: string;
          title: string;
          severity: string;
          status: string;
        }>;
      }>("/api/incidents", jwt),
    ]);
    setKpis(dash.kpis);
    setIncidents(incRes.incidents);
  };

  const handleLogin = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await mobileApi<{ token: string; user: { name: string } }>(
        "/api/auth/login",
        null,
        {
          method: "POST",
          body: JSON.stringify({ email, password }),
        }
      );
      setToken(res.token);
      setUserName(res.user.name);
      await loadSocOverview(res.token);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleRunScan = async () => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const payload =
        scanMode === "url"
          ? { url: target }
          : scanMode === "ip"
          ? { ip: target }
          : { cveId: target };
      const res = await mobileApi<{ scan: ScanSummary }>(
        `/api/scans/${scanMode}`,
        token,
        {
          method: "POST",
          body: JSON.stringify(payload),
        }
      );
      setScanResult(res.scan);
      await loadSocOverview(token);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!token) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#050811" />
        <View style={styles.authCard}>
          <Text style={styles.brand}>THREATLENS AI · ANDROID SOC</Text>
          <Text style={styles.tagline}>
            Detect threats. Investigate evidence. Understand risks. Protect systems.
          </Text>
          {error && <Text style={styles.errorText}>{error}</Text>}
          <TextInput
            style={styles.input}
            value={email}
            onChangeText={setEmail}
            placeholder="Email"
            placeholderTextColor="#64748B"
            autoCapitalize="none"
          />
          <TextInput
            style={styles.input}
            value={password}
            onChangeText={setPassword}
            placeholder="Password"
            placeholderTextColor="#64748B"
            secureTextEntry
          />
          <TouchableOpacity
            style={styles.primaryBtn}
            onPress={handleLogin}
            disabled={busy}
          >
            <Text style={styles.primaryBtnText}>
              {busy ? "Signing In..." : "Sign In to Mobile SOC"}
            </Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#050811" />
      <View style={styles.header}>
        <View>
          <Text style={styles.brand}>THREATLENS AI</Text>
          <Text style={styles.subtle}>{userName}</Text>
        </View>
        <TouchableOpacity onPress={() => setToken(null)}>
          <Text style={styles.logoutText}>Sign Out</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.tabRow}>
        {(["dashboard", "scan", "incidents"] as const).map((t) => (
          <TouchableOpacity
            key={t}
            onPress={() => setTab(t)}
            style={[styles.tabBtn, tab === t && styles.tabBtnActive]}
          >
            <Text style={styles.tabText}>{t.toUpperCase()}</Text>
          </TouchableOpacity>
        ))}
      </View>

      <ScrollView contentContainerStyle={styles.scrollBody}>
        {error && <Text style={styles.errorText}>{error}</Text>}

        {tab === "dashboard" && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>Live SOC Telemetry</Text>
            {Object.entries(kpis).map(([key, val]) => (
              <View key={key} style={styles.card}>
                <Text style={styles.subtle}>{key}</Text>
                <Text style={styles.kpiValue}>{val}</Text>
              </View>
            ))}
          </View>
        )}

        {tab === "scan" && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>Field Threat Scanner</Text>
            <View style={styles.tabRow}>
              {(["url", "ip", "cve"] as const).map((m) => (
                <TouchableOpacity
                  key={m}
                  onPress={() => {
                    setScanMode(m);
                    setTarget(
                      m === "url"
                        ? "http://microsoft-verify-sso.xyz/login"
                        : m === "ip"
                        ? "45.95.147.22"
                        : "CVE-2024-3094"
                    );
                  }}
                  style={[styles.tabBtn, scanMode === m && styles.tabBtnActive]}
                >
                  <Text style={styles.tabText}>{m.toUpperCase()}</Text>
                </TouchableOpacity>
              ))}
            </View>
            <TextInput
              style={styles.input}
              value={target}
              onChangeText={setTarget}
              autoCapitalize="none"
            />
            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={handleRunScan}
              disabled={busy}
            >
              <Text style={styles.primaryBtnText}>
                {busy ? "Scanning..." : `Analyze ${scanMode.toUpperCase()}`}
              </Text>
            </TouchableOpacity>

            {scanResult && (
              <View style={styles.card}>
                <Text style={styles.kpiValue}>
                  Risk: {scanResult.riskScore}/100 ({scanResult.severity})
                </Text>
                <Text style={styles.brand}>{scanResult.verdict}</Text>
                <Text style={styles.subtle}>{scanResult.summary}</Text>
              </View>
            )}
          </View>
        )}

        {tab === "incidents" && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>Active SOC Incidents</Text>
            {incidents.map((inc) => (
              <View key={inc.id} style={styles.card}>
                <Text style={styles.brand}>
                  {inc.code} · {inc.severity}
                </Text>
                <Text style={styles.cardTitle}>{inc.title}</Text>
                <Text style={styles.subtle}>Status: {inc.status}</Text>
              </View>
            ))}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#050811" },
  header: {
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: "#1E293B",
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  authCard: {
    margin: 20,
    marginTop: 90,
    padding: 24,
    borderRadius: 16,
    backgroundColor: "#0B1120",
    borderWidth: 1,
    borderColor: "#1E293B",
    gap: 12,
  },
  brand: { color: "#06B6D4", fontWeight: "700", fontSize: 14 },
  tagline: { color: "#94A3B8", fontSize: 12, marginBottom: 8 },
  subtle: { color: "#94A3B8", fontSize: 12, marginTop: 4 },
  logoutText: { color: "#F87171", fontSize: 12, fontWeight: "600" },
  input: {
    backgroundColor: "#020617",
    borderColor: "#1E293B",
    borderWidth: 1,
    borderRadius: 10,
    padding: 12,
    color: "#F8FAFC",
    fontSize: 13,
  },
  primaryBtn: {
    backgroundColor: "#06B6D4",
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: "center",
  },
  primaryBtnText: { color: "#020617", fontWeight: "700", fontSize: 13 },
  tabRow: { flexDirection: "row", gap: 8, paddingHorizontal: 16, paddingVertical: 10 },
  tabBtn: {
    flex: 1,
    paddingVertical: 8,
    borderRadius: 8,
    backgroundColor: "#0B1120",
    borderWidth: 1,
    borderColor: "#1E293B",
    alignItems: "center",
  },
  tabBtnActive: { borderColor: "#06B6D4", backgroundColor: "#083344" },
  tabText: { color: "#E2E8F0", fontSize: 11, fontWeight: "700" },
  scrollBody: { padding: 16, gap: 12 },
  section: { gap: 10 },
  sectionTitle: { color: "#F8FAFC", fontSize: 16, fontWeight: "700" },
  card: {
    padding: 14,
    borderRadius: 12,
    backgroundColor: "#0B1120",
    borderWidth: 1,
    borderColor: "#1E293B",
  },
  cardTitle: { color: "#F8FAFC", fontSize: 14, fontWeight: "600", marginTop: 4 },
  kpiValue: { color: "#F8FAFC", fontSize: 22, fontWeight: "800", marginTop: 4 },
  errorText: { color: "#FCA5A5", fontSize: 12 },
});

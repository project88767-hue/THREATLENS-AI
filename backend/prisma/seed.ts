import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  console.log("[THREATLENS SEED] Seeding clearly labelled DEMO SOC telemetry...");

  const [adminHash, analystHash, viewerHash] = await Promise.all([
    bcrypt.hash("Admin@12345", 12),
    bcrypt.hash("Analyst@12345", 12),
    bcrypt.hash("Viewer@12345", 12),
  ]);

  const admin = await prisma.user.upsert({
    where: { email: "admin@threatlens.demo" },
    update: { name: "Aashutosh Sharma (SOC Director)", role: "ADMIN", status: "ACTIVE" },
    create: {
      email: "admin@threatlens.demo",
      name: "Aashutosh Sharma (SOC Director)",
      passwordHash: adminHash,
      role: "ADMIN",
      department: "Security Architecture & Governance",
      lastLoginAt: new Date(),
    },
  });

  const analyst = await prisma.user.upsert({
    where: { email: "analyst@threatlens.demo" },
    update: { name: "Riya Verma (Tier-3 Threat Hunter)", role: "ANALYST", status: "ACTIVE" },
    create: {
      email: "analyst@threatlens.demo",
      name: "Riya Verma (Tier-3 Threat Hunter)",
      passwordHash: analystHash,
      role: "ANALYST",
      department: "Threat Intelligence & IR",
      lastLoginAt: new Date(),
    },
  });

  await prisma.user.upsert({
    where: { email: "viewer@threatlens.demo" },
    update: { name: "Vikram Nair (Compliance Auditor)", role: "VIEWER", status: "ACTIVE" },
    create: {
      email: "viewer@threatlens.demo",
      name: "Vikram Nair (Compliance Auditor)",
      passwordHash: viewerHash,
      role: "VIEWER",
      department: "GRC & Audit",
    },
  });

  // Clean prior demo records to avoid duplicates on re-seed
  await prisma.report.deleteMany({ where: { isDemoData: true } });
  await prisma.incident.deleteMany({ where: { isDemoData: true } });
  await prisma.threatRelation.deleteMany({ where: { isDemoData: true } });
  await prisma.scanResult.deleteMany({ where: { isDemoData: true } });
  await prisma.investigation.deleteMany({ where: { isDemoData: true } });
  await prisma.indicator.deleteMany({ where: { isDemoData: true } });

  // Create Demo Investigations
  const invPhish = await prisma.investigation.create({
    data: {
      code: "INV-2026-001",
      title: "[DEMO] Operation SilverLure — Executive M365 Spear-Phishing & C2",
      description:
        "Coordinated credential-harvesting campaign impersonating corporate SSO login portals using newly registered .xyz lookalike domains and offshore relay IPs.",
      status: "ESCALATED",
      priority: "CRITICAL",
      tags: ["demo-data", "spear-phishing", "bec", "credential-harvest"],
      aiSummary:
        "High-confidence spear-phishing campaign combining DMARC-failing executive spoofed emails, newly registered domain microsoft-verify-sso.xyz (6 days old), and C2 callback IP 45.95.147.22.",
      isDemoData: true,
      ownerId: analyst.id,
      notes: {
        create: [
          {
            authorId: analyst.id,
            content:
              "[DEMO NOTE] Confirmed 14 inbound messages bypassed legacy spam filter from Reply-To wire-desk@microsoft-verify-sso.xyz. Quarantining messages and sinkholing domain.",
            isAiGenerated: false,
          },
          {
            authorId: admin.id,
            content:
              "[DEMO AI COPILOT] Mapped campaign to MITRE ATT&CK T1566.002 (Spearphishing Link) and T1656 (Impersonation). Recommended immediate OAuth refresh token revocation.",
            isAiGenerated: true,
          },
        ],
      },
    },
  });

  const invVuln = await prisma.investigation.create({
    data: {
      code: "INV-2026-002",
      title: "[DEMO] Perimeter Gateway CVE-2024-3094 & CVE-2024-21762 Exposure Audit",
      description:
        "Proactive vulnerability intelligence sweep across external Linux bastions and VPN concentrators following CISA KEV advisory.",
      status: "IN_PROGRESS",
      priority: "HIGH",
      tags: ["demo-data", "cve-triage", "cisa-kev", "patch-sla"],
      isDemoData: true,
      ownerId: admin.id,
    },
  });

  // Seed Demo Indicators & ScanResults spread across last 6 days for rich dashboard charts
  const demoScans = [
    {
      daysAgo: 5,
      type: "URL" as const,
      value: "http://microsoft-verify-sso.xyz/login/credential-update",
      riskScore: 92,
      severity: "CRITICAL" as const,
      verdict: "MALICIOUS" as const,
      invId: invPhish.id,
      summary:
        "[DEMO] URL flagged CRITICAL (92/100): Newly registered typosquat domain, unencrypted HTTP, credential lure path, and multi-engine detections.",
      breakdown: [
        {
          factor: "VirusTotal Reputation (Demo)",
          points: 30,
          max_points: 35,
          reason: "16 security vendors flagged phishing infrastructure.",
          source: "VirusTotal (Demo)",
          is_simulated: true,
        },
        {
          factor: "Google Safe Browsing (Demo)",
          points: 25,
          max_points: 30,
          reason: "Matched SOCIAL_ENGINEERING blocklist.",
          source: "Safe Browsing (Demo)",
          is_simulated: true,
        },
        {
          factor: "Lexical Phishing & NRD Age",
          points: 37,
          max_points: 45,
          reason: "6-day-old .xyz domain imitating Microsoft SSO over HTTP.",
          source: "THREATLENS Engine",
          is_simulated: false,
        },
      ],
      provider: "SAFE_BROWSING",
      evTitle: "[DEMO] Matched SOCIAL_ENGINEERING phishing signature",
    },
    {
      daysAgo: 4,
      type: "EMAIL" as const,
      value: "ceo-urgent-desk@offshore-mail.xyz",
      riskScore: 88,
      severity: "CRITICAL" as const,
      verdict: "MALICIOUS" as const,
      invId: invPhish.id,
      summary:
        "[DEMO] Spear-phishing BEC email failed SPF, DKIM, and DMARC with Reply-To mismatch and urgent wire transfer lure.",
      breakdown: [
        {
          factor: "SPF/DKIM/DMARC Alignment",
          points: 38,
          max_points: 40,
          reason: "SPF=fail, DKIM=fail, DMARC=fail.",
          source: "Email Auth Parser",
          is_simulated: false,
        },
        {
          factor: "Header Spoofing & BEC Lures",
          points: 50,
          max_points: 60,
          reason: "Executive display-name impersonation + Reply-To mismatch + wire transfer urgency.",
          source: "BEC Heuristics",
          is_simulated: false,
        },
      ],
      provider: "EMAIL_AUTH_PARSER",
      evTitle: "[DEMO] Email Auth: SPF=FAIL, DKIM=FAIL, DMARC=FAIL",
    },
    {
      daysAgo: 3,
      type: "IP" as const,
      value: "45.95.147.22",
      riskScore: 94,
      severity: "CRITICAL" as const,
      verdict: "MALICIOUS" as const,
      invId: invPhish.id,
      summary:
        "[DEMO] Offshore C2 & phishing host IP 45.95.147.22 carries 98% AbuseIPDB confidence across 612 reports.",
      breakdown: [
        {
          factor: "AbuseIPDB Confidence (Demo)",
          points: 39,
          max_points: 40,
          reason: "98% abuse confidence (612 community reports).",
          source: "AbuseIPDB (Demo)",
          is_simulated: true,
        },
        {
          factor: "VirusTotal & OTX Pulses (Demo)",
          points: 45,
          max_points: 55,
          reason: "22 vendor hits + 6 OTX Cobalt Strike / phishing pulses.",
          source: "VT + OTX (Demo)",
          is_simulated: true,
        },
      ],
      provider: "ABUSEIPDB",
      evTitle: "[DEMO] AbuseIPDB Confidence: 98% (612 reports)",
    },
    {
      daysAgo: 2,
      type: "DOMAIN" as const,
      value: "microsoft-verify-sso.xyz",
      riskScore: 81,
      severity: "HIGH" as const,
      verdict: "MALICIOUS" as const,
      invId: invPhish.id,
      summary:
        "[DEMO] Brand typosquatting domain registered 6 days ago on high-abuse .xyz TLD.",
      breakdown: [
        {
          factor: "Brand Impersonation & TLD Risk",
          points: 34,
          max_points: 35,
          reason: "Unauthorized 'microsoft' brand token on .xyz TLD.",
          source: "Domain Forensics",
          is_simulated: false,
        },
        {
          factor: "RDAP Newly Registered Domain",
          points: 22,
          max_points: 25,
          reason: "Domain age is 6 days (<45d NRD threshold).",
          source: "RDAP (Demo)",
          is_simulated: true,
        },
      ],
      provider: "RDAP",
      evTitle: "[DEMO] Newly Registered Domain (6 days old)",
    },
    {
      daysAgo: 1,
      type: "CVE" as const,
      value: "CVE-2024-3094",
      riskScore: 98,
      severity: "CRITICAL" as const,
      verdict: "MALICIOUS" as const,
      invId: invVuln.id,
      summary:
        "[DEMO] XZ Utils liblzma supply-chain backdoor (CVSS 10.0 CRITICAL, CISA KEV listed).",
      breakdown: [
        {
          factor: "CVSS v3.1 Base Score",
          points: 65,
          max_points: 65,
          reason: "CVSS 10.0 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C).",
          source: "NIST NVD",
          is_simulated: true,
        },
        {
          factor: "CISA KEV Active Exploitation",
          points: 25,
          max_points: 25,
          reason: "Confirmed supply-chain backdoor advisory.",
          source: "KEV Intelligence",
          is_simulated: true,
        },
      ],
      provider: "NVD",
      evTitle: "[DEMO] CVSS 10.0 CRITICAL — CWE-506 Embedded Malicious Code",
    },
    {
      daysAgo: 0,
      type: "IP" as const,
      value: "8.8.8.8",
      riskScore: 4,
      severity: "LOW" as const,
      verdict: "CLEAN" as const,
      invId: null,
      summary:
        "[DEMO] Verified Google Public DNS resolver (0% abuse confidence, clean reputation).",
      breakdown: [
        {
          factor: "AbuseIPDB & VirusTotal Baseline",
          points: 0,
          max_points: 75,
          reason: "Trusted public DNS infrastructure.",
          source: "Multi-Provider",
          is_simulated: true,
        },
      ],
      provider: "ABUSEIPDB",
      evTitle: "[DEMO] 0% Abuse Confidence (Google LLC Public DNS)",
    },
  ];

  for (const item of demoScans) {
    const createdAt = new Date(Date.now() - item.daysAgo * 24 * 60 * 60 * 1000);
    const ind = await prisma.indicator.create({
      data: {
        type: item.type,
        value: item.value,
        normalizedValue: item.value.toLowerCase(),
        riskScore: item.riskScore,
        severity: item.severity,
        confidence: 91,
        verdict: item.verdict,
        tags: ["demo-data", item.type.toLowerCase()],
        isDemoData: true,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
      },
    });

    await prisma.scanResult.create({
      data: {
        indicatorId: ind.id,
        userId: analyst.id,
        investigationId: item.invId,
        scanType: item.type,
        targetValue: item.value,
        normalizedValue: item.value.toLowerCase(),
        riskScore: item.riskScore,
        severity: item.severity,
        confidence: 91,
        verdict: item.verdict,
        summary: item.summary,
        aiExplanation: {
          overview: item.summary,
          why_flagged: item.breakdown.map((b) => `${b.factor}: ${b.reason}`),
          mitre_techniques: [
            { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access" },
          ],
          recommended_actions: [
            "Enforce perimeter DNS/SWG blocklist rules.",
            "Audit 30-day SIEM telemetry for matching host connections.",
          ],
          is_simulated_ai: true,
        },
        scoreBreakdown: item.breakdown,
        providerStatus: {
          heuristic_engine: { mode: "LIVE", latency_ms: 2, message: "Seeded demo baseline" },
          demo_feed: { mode: "DEMO_FALLBACK", latency_ms: 5, message: "Clearly labelled demo data" },
        },
        metadata: { demoSeeded: true },
        isDemoData: true,
        createdAt,
        evidence: {
          create: [
            {
              investigationId: item.invId,
              provider: item.provider,
              category: "Seeded Threat Telemetry (Demo Data)",
              title: item.evTitle,
              verdict: item.verdict,
              weight: item.riskScore,
              details: { demoData: true, indicator: item.value },
              isSimulated: true,
              createdAt,
            },
          ],
        },
      },
    });
  }

  // Create Demo Threat Relationship Graph Edges
  await prisma.threatRelation.createMany({
    data: [
      {
        sourceType: "CAMPAIGN",
        sourceValue: "operation-silverlure",
        sourceLabel: "[DEMO] Op SilverLure",
        targetType: "EMAIL",
        targetValue: "ceo-urgent-desk@offshore-mail.xyz",
        targetLabel: "ceo-urgent-desk@offshore-mail.xyz",
        relation: "OPERATES_SENDER",
        confidence: 94,
        severity: "CRITICAL",
        isDemoData: true,
        investigationId: invPhish.id,
      },
      {
        sourceType: "EMAIL",
        sourceValue: "ceo-urgent-desk@offshore-mail.xyz",
        sourceLabel: "ceo-urgent-desk@offshore-mail.xyz",
        targetType: "URL",
        targetValue: "http://microsoft-verify-sso.xyz/login/credential-update",
        targetLabel: "microsoft-verify-sso.xyz/login/...",
        relation: "SENDS_PHISHING",
        confidence: 96,
        severity: "CRITICAL",
        isDemoData: true,
        investigationId: invPhish.id,
      },
      {
        sourceType: "URL",
        sourceValue: "http://microsoft-verify-sso.xyz/login/credential-update",
        sourceLabel: "microsoft-verify-sso.xyz/login/...",
        targetType: "DOMAIN",
        targetValue: "microsoft-verify-sso.xyz",
        targetLabel: "microsoft-verify-sso.xyz",
        relation: "HOSTED_ON",
        confidence: 99,
        severity: "HIGH",
        isDemoData: true,
        investigationId: invPhish.id,
      },
      {
        sourceType: "DOMAIN",
        sourceValue: "microsoft-verify-sso.xyz",
        sourceLabel: "microsoft-verify-sso.xyz",
        targetType: "IP",
        targetValue: "45.95.147.22",
        targetLabel: "45.95.147.22 (NL C2)",
        relation: "RESOLVES_TO",
        confidence: 95,
        severity: "CRITICAL",
        isDemoData: true,
        investigationId: invPhish.id,
      },
      {
        sourceType: "IP",
        sourceValue: "45.95.147.22",
        sourceLabel: "45.95.147.22 (NL C2)",
        targetType: "CVE",
        targetValue: "CVE-2024-21762",
        targetLabel: "CVE-2024-21762 (FortiOS)",
        relation: "SCANS_FOR_CVE",
        confidence: 84,
        severity: "HIGH",
        isDemoData: true,
        investigationId: invVuln.id,
      },
      {
        sourceType: "CVE",
        sourceValue: "CVE-2024-3094",
        sourceLabel: "CVE-2024-3094 (XZ Backdoor)",
        targetType: "ASSET",
        targetValue: "bastion-ssh-eu-01.corp.demo",
        targetLabel: "bastion-ssh-eu-01 (Demo Lab)",
        relation: "IMPACTS_ASSET",
        confidence: 90,
        severity: "CRITICAL",
        isDemoData: true,
        investigationId: invVuln.id,
      },
    ],
  });

  // Create Demo Incidents
  const inc1 = await prisma.incident.create({
    data: {
      code: "INC-2026-001",
      title: "[DEMO] Finance & Executive M365 Spear-Phishing Containment",
      summary:
        "Active containment of Operation SilverLure spear-phishing campaign targeting Finance team with spoofed CFO wire-transfer emails and credential harvester link.",
      severity: "CRITICAL",
      status: "CONTAINED",
      affectedAssets: [
        "m365-exchange-prod (Demo)",
        "fin-wkstn-04.corp.demo",
        "sso-idp-gateway.corp.demo",
      ],
      mitreTechniques: ["T1566.002", "T1656", "T1078"],
      playbookSteps: [
        {
          id: "pb-1",
          phase: "Identification",
          task: "Confirm recipient list & proxy click logs in SIEM",
          completed: true,
        },
        {
          id: "pb-2",
          phase: "Containment",
          task: "Sinkhole microsoft-verify-sso.xyz and block 45.95.147.22 on Firewall",
          completed: true,
        },
        {
          id: "pb-3",
          phase: "Containment",
          task: "Revoke OAuth sessions & enforce FIDO2 MFA reset for 2 clicked users",
          completed: true,
        },
        {
          id: "pb-4",
          phase: "Eradication",
          task: "Purge 14 spoofed emails from Exchange mailboxes and update DMARC policy",
          completed: false,
        },
        {
          id: "pb-5",
          phase: "Recovery",
          task: "Complete 48-hour post-containment sign-in anomaly watch",
          completed: false,
        },
      ],
      isDemoData: true,
      assignedToId: analyst.id,
      investigationId: invPhish.id,
    },
  });

  await prisma.incident.create({
    data: {
      code: "INC-2026-002",
      title: "[DEMO] Emergency Bastion OpenSSH / XZ Package Verification",
      summary:
        "Verify liblzma package versions across Linux build runners and external SSH bastions for CVE-2024-3094.",
      severity: "HIGH",
      status: "TRIAGING",
      affectedAssets: ["bastion-ssh-eu-01.corp.demo", "ci-runner-pool-02.corp.demo"],
      mitreTechniques: ["T1195.002", "T1190"],
      playbookSteps: [
        {
          id: "pb-v1",
          phase: "Identification",
          task: "Query fleet SBOM inventory for xz-utils 5.6.0 / 5.6.1",
          completed: true,
        },
        {
          id: "pb-v2",
          phase: "Containment",
          task: "Restrict SSH ingress strictly to corporate WireGuard management CIDR",
          completed: false,
        },
        {
          id: "pb-v3",
          phase: "Eradication",
          task: "Pin verified xz-utils 5.4.5 packages and rotate host keys",
          completed: false,
        },
      ],
      isDemoData: true,
      assignedToId: admin.id,
      investigationId: invVuln.id,
    },
  });

  // Create Demo Report
  await prisma.report.create({
    data: {
      code: "RPT-2026-001",
      title: "[DEMO] Executive Threat Assessment — Operation SilverLure Phishing Campaign",
      format: "EXECUTIVE",
      summary:
        "Executive incident briefing detailing rapid detection, explainable risk scoring, and containment of the Operation SilverLure credential-harvesting campaign with zero data loss.",
      findingsMarkdown: [
        "# [DEMO] Operation SilverLure — Executive Incident & Threat Report",
        "**Classification:** `TLP:AMBER (Demo Portfolio Sample)` | **Prepared By:** THREATLENS AI SOC",
        "",
        "## 1. Executive Summary",
        "THREATLENS AI detected and correlated a targeted spear-phishing campaign (`INV-2026-001`) utilizing a newly registered lookalike domain (`microsoft-verify-sso.xyz`) hosted on `45.95.147.22`. All impacted sessions were revoked within 18 minutes of alert triage.",
        "",
        "## 2. Key Risk Indicators",
        "- **URL Indicator:** `http://microsoft-verify-sso.xyz/login/credential-update` — **92/100 CRITICAL**",
        "- **Sender Indicator:** `ceo-urgent-desk@offshore-mail.xyz` — **88/100 CRITICAL** (SPF/DKIM/DMARC Fail)",
        "- **C2 Infrastructure:** `45.95.147.22` — **94/100 CRITICAL** (98% AbuseIPDB Confidence)",
        "",
        "## 3. Strategic Security Recommendations",
        "1. Transition corporate domains to **DMARC `p=reject`** enforcement.",
        "2. Block newly registered domains (<30 days) on `.xyz`, `.top`, and `.tk` TLDs at Secure Web Gateway.",
        "3. Mandate phishing-resistant **WebAuthn / FIDO2 passkeys** for Finance and Executive roles.",
      ].join("\n"),
      riskOverview: {
        analyzedCount: 4,
        averageRiskScore: 89,
        peakRiskScore: 94,
        generatedAt: new Date().toISOString(),
      },
      recommendations: [
        "Enforce DMARC p=reject across external mail domains.",
        "Block NRD domains (<30 days) at DNS sinkhole.",
        "Require FIDO2 hardware/passkey MFA for privileged workflows.",
      ],
      isDemoData: true,
      investigationId: invPhish.id,
      incidentId: inc1.id,
      generatedById: admin.id,
    },
  });

  await prisma.auditLog.create({
    data: {
      userId: admin.id,
      actorEmail: admin.email,
      action: "DEMO_DATA_SEEDED",
      resourceType: "System",
      status: "SUCCESS",
      ipAddress: "127.0.0.1",
      userAgent: "prisma-seed-cli",
      metadata: { note: "Initial portfolio demo dataset initialized" },
    },
  });

  console.log("[THREATLENS SEED] Demo dataset seeded successfully!");
}

main()
  .catch((err) => {
    console.error("[THREATLENS SEED ERROR]", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

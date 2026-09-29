# SOC Analyst Career and Portfolio Guide

This guide explains how to use SOC Desk as a practice and portfolio project, how to discuss it honestly in interviews, and what the available market evidence does and does not say. It is not a live vacancy or salary survey.

## Market Snapshot

### Bulgaria

Public SOC-specific vacancy data for Bulgaria was not accessible for a reliable count during this review: major job-board pages blocked automated access or required sign-in. Do not treat this guide as a count of Bulgarian SOC openings or as salary advice. Check live postings in Bulgarian and English before tailoring each application.

The best accessible local proxy is broader ICT hiring data from Eurostat. Its article, with data extracted in June 2025, says 57.5% of EU enterprises that recruited or tried to recruit ICT specialists reported difficulty filling those vacancies in 2023. It also reports that 51.42% of Bulgarian enterprises outsourced ICT functions in 2023, compared with 71.92% across the EU. These figures cover general ICT functions, not SOC teams or cybersecurity roles specifically. They suggest that local employers may use a mix of in-house and provider-based IT operations, but they do not prove the size or structure of Bulgaria's SOC market.

For a Bulgarian search, investigate both in-house security teams and service providers/MSSPs, plus employers in finance, telecom, technology, and multinational shared-service environments. Treat those as search avenues, not claims that a given sector is hiring now. Expect requirements to differ by employer: language, shift schedule, location/hybrid policy, tool stack, and whether the job is true alert triage or broader IT support should be confirmed in the vacancy and interview.

### Europe and Global

The World Economic Forum's 2025 employer survey projects networks and cybersecurity among the fastest-growing skill areas through 2030. That is a broad employer outlook, not a guarantee that every country or SOC role will grow at the same rate.

ISC2's 2025 Cybersecurity Workforce Study surveyed 16,029 practitioners and decision-makers across North America, Latin America, Asia-Pacific, and EMEA. Respondents emphasized skills needs, including AI, cloud security, risk assessment, application security, security engineering, and GRC. The study says traditional roles such as SOC analyst and incident responder are evolving; it does not measure Bulgarian vacancies.

ISC2's 2025 entry/junior hiring study surveyed 929 managers in Canada, Germany, India, Japan, the UK, and the US, not Bulgaria. In that sample, 90% said they would consider someone with only previous IT work experience, 89% someone with only an entry-level cybersecurity certification, and 84% reported using a skills-based assessment or test for entry/junior candidates. Hiring managers highlighted problem-solving, teamwork, analytical thinking, communication, and willingness to learn alongside technical foundations. These are survey responses, not universal requirements, but they support practicing and explaining real work rather than listing tools alone.

The NIST NICE Framework provides a common vocabulary for work roles and their task, knowledge, and skill statements. Use the current version to compare the wording in actual job listings with the skills you can demonstrate.

### What to Prepare For

Entry-level SOC work commonly involves checking alert context, validating whether the signal is supported by evidence, identifying the affected account/device/time window, documenting findings, following playbooks and SLAs, and escalating when the evidence or impact warrants it. A SOC analyst is not expected to independently make every containment decision; authority and escalation boundaries are employer-specific.

Build practical fluency in:

- Windows event logs, basic Linux logs, authentication, and identity concepts.
- TCP/IP, DNS, HTTP, common ports, and how proxies/firewalls affect observations.
- SIEM searches and alert triage; EDR alert context and process trees.
- Basic incident lifecycle, evidence notes, severity, false-positive reasoning, and handoffs.
- Clear written English; add Bulgarian or another language when a specific role asks for it.
- Team communication, analytical thinking, calm prioritization, and willingness to learn.

For each application, copy the employer's actual requirements into a matrix: **required**, **preferred**, **I can demonstrate**, and **I am still learning**. Never claim a product, certification, or production experience you do not have.

## What This App Demonstrates

SOC Desk is a local, single-user casebook and learning aid. It supports synthetic alerts, approved CSV copies, local case notes/status/history, filtered and paginated review, CSV export, and bounded TCP observations on an explicitly authorized private IPv4 scope.

It is not a SIEM/EDR integration, live alert listener, ticketing system, packet sensor, CVE scanner, or incident response automation platform. The SQLite database is local and unencrypted. Do not import employer telemetry or run scans at work without explicit approval and an approved scope. The actual system of record and the organization's playbook remain authoritative.

Positive engineering points you can explain:

- A separate data layer keeps case persistence and CSV handling out of most UI code.
- SQLite uses parameterized queries, transactions, source-scoped duplicate IDs, and an action history.
- Queue pagination and SQL-side dashboard counts keep large imports from forcing the UI to render every record.
- The demo cases use clearly labeled synthetic records and reserved example IP ranges.
- Network observations are bounded and labeled as leads; service exposure is not represented as a confirmed vulnerability.
- Tests cover CSV mapping, duplicate handling, triage history, filters, pagination, monitor baselines, and input bounds.

Known limitations worth mentioning constructively:

- No live vendor connectors, API sync, user/role permissions, encrypted case database, retention controls, or multi-user collaboration.
- CSV field names and timestamps vary by vendor; imported fields need source verification.
- The local monitor checks selected TCP ports periodically and, on Windows, reads the OS IPv4 neighbor cache after those probes. Cache entries can be stale; other platforms rely on TCP responses. It misses brief flows, UDP, and packets between checks; it cannot prove a CVE or malicious activity.
- Production readiness would require a security review, access controls, protected storage, audit/retention policy, reliable integrations, packaging/signing, and organization-specific testing.

## Using the App for Practice

1. Run `py Main.py` from the project directory.
2. Open **Alert queue** and select **Load demo cases**. All examples are synthetic and safe for a portfolio demonstration.
3. Filter by severity/status and use the page controls to explore the queue.
4. Select a case. Read the detection, affected asset/account, time, source, and description before forming a conclusion.
5. Write factual notes: evidence checked, what it showed, what remains unknown, and the next action/owner. Do not invent evidence the app did not collect.
6. Set the disposition and status. Use **Escalated** for a practice handoff; explain that real escalation follows the employer's process.
7. Review case history and export a CSV if you want to inspect the resulting record.
8. Use the one-time or scheduled network tools only on a lab network you own or are explicitly authorized to test. Do not use a job interview or employer network as a test target.

Practice an investigation narrative with a four-part structure:

1. **Signal:** What exactly did the alert claim, and when?
2. **Validation:** What data would you check in the SIEM/EDR/identity source, and what did the synthetic record actually show?
3. **Assessment:** What supports or weakens the hypothesis? What is still unknown?
4. **Action:** What would you document, monitor, close, or escalate under a real team's playbook?

## Interview Walkthrough

Keep a demo to about five minutes:

1. State that this is a personal Python/Tkinter project and a local casebook, not a production SIEM.
2. Load the synthetic cases and show severity/status filters and pagination.
3. Select the PowerShell or sign-in scenario. Talk through what the alert establishes, what it does not, and which source records you would verify.
4. Add a concise note, set **In progress** or **Escalated**, and show the audit history.
5. Show the CSV export and explain duplicate handling and formula-safe output.
6. If asked about the network tab, explain its scope/interval caps, Windows neighbor-cache source, and stale-entry caveat. TCP responses are exposure leads, not vulnerability verdicts.
7. Close with one limitation and a sensible next step, such as a read-only connector to a lab SIEM, access/retention controls, or a sanitized event-normalization test suite.

Example explanation for the PowerShell demo:

> "This synthetic alert says an Office process launched encoded PowerShell. I would not label that malicious from the title alone. In a real EDR, I would inspect the parent/child process chain, command line, user and host context, file origin, network activity, and the detection's action result; then correlate the time window in the SIEM. I would document what I verified and escalate according to the team's playbook if evidence or impact crossed the threshold. This app stores practice triage notes but does not collect those endpoint events itself."

## CV Wording

Project title: **SOC Desk - Python SOC Triage Casebook**

CV bullets, use only if you can explain the implementation:

- Built a Python/Tkinter SOC triage casebook with CSV alert ingestion, SQLite persistence, source-scoped duplicate handling, case history, analyst notes, severity/status filtering, pagination, and CSV export.
- Added synthetic alert scenarios and tested triage, filter, pagination, and persistence workflows with Python unit tests.
- Implemented explicitly scoped IPv4 TCP observations with per-cycle `.logs` output, cancellation, and review-only exposure heuristics; documented that these checks do not confirm vulnerabilities or capture traffic.

Label it **personal project** or **portfolio project**. Do not list it under professional SOC employment, describe the sample alerts as real incidents, claim SIEM/EDR integration, or imply that you have used it to respond to production incidents.

## Questions to Ask the Employer

- Which SIEM, EDR, identity, and ticketing tools does the team use day to day?
- What does a normal L1 shift look like, and how are nights/weekends/rotations handled?
- Which cases can an L1 close, and which actions require escalation or approval?
- How are severity, SLAs, case handoffs, and quality reviewed?
- What training, shadowing, and progression to L2/incident response are provided?
- Which languages, location, on-call, and hybrid requirements are essential for this particular role?

## Sources and Scope Notes

- [NIST NICE Framework current versions](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions), version 2.2.0 published April 2025; page updated May 2026.
- [ISC2 2025 Cybersecurity Hiring Trends](https://www.isc2.org/Insights/2025/06/cybersecurity-hiring-trends-study), a 929-manager survey in six countries: Canada, Germany, India, Japan, UK, and US.
- [ISC2 2025 Cybersecurity Workforce Study](https://www.isc2.org/Insights/2025/12/2025-ISC2-Cybersecurity-Workforce-Study), survey of 16,029 cybersecurity practitioners and decision-makers across several world regions.
- [World Economic Forum Future of Jobs 2025 digest](https://www.weforum.org/publications/the-future-of-jobs-report-2025/digest/), employer expectations through 2030 across 55 economies.
- [Eurostat: ICT specialists and hard-to-fill vacancies](https://ec.europa.eu/eurostat/statistics-explained/index.php?title=ICT_specialists_-_statistics_on_hard-to-fill_vacancies_in_enterprises), data extracted June 2025; covers general ICT specialists, not SOC-specific hiring.

Job-board pages for Bulgaria were not accessible for a representative posting sample during this review. Therefore this guide does not claim a Bulgarian SOC vacancy count, country-specific salary range, or definitive list of required tools. Re-check live postings and employer requirements before applying.
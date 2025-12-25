# 🏥 Medical Database Security Hardening
**Tech Stack:** SQL Server (T-SQL), AES-256 Encryption, RBAC, Temporal Tables

## 📄 Project Overview
This project implements a "Defense-in-Depth" security architecture for a hospital management system. It secures sensitive Protected Health Information (PHI) compliant with HIPAA/GDPR standards.

## 🛡️ Key Features Implemented
* **Column-Level Encryption:** Sensitive data (Diagnosis, PII) is encrypted using **AES-256** with a 3-tier key hierarchy (Master Key -> Certificate -> Symmetric Key).
* **Role-Based Access Control (RBAC):** Strict separation of duties between Doctors, Nurses, and Patients using Schema Access Restrictions (`DENY SELECT` on raw tables).
* **Immutable Audit Trails:** Implemented **System-Versioned Temporal Tables** to track every historical change to medical records.
* **Fail-Safe Triggers:** Database-level triggers prevent the accidental or malicious deletion of diagnosed records (Error 54000).

## 🚀 How to Run
1. Open `MIS.sql` in SSMS.
2. Execute Phase 1 (Infrastructure) to build the schema.
3. Execute Phases 2-7 to apply security layers.

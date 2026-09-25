+++
title = "SMB Settings"
+++

Administrators configure Sambee's runtime SMB behavior in **Settings** > **Administration** > **SMB**. These controls apply to every configured SMB connection.

## Protection

### Authentication Mode

- **Automatic (Kerberos or NTLM)** uses Kerberos when available and otherwise falls back to NTLM. This is the practical option for compatible domain and NAS environments.
- **Kerberos required** blocks NTLM fallback. Choose it when every SMB server is correctly configured for Kerberos authentication.

### Transport Protection

SMB signing is always required by Sambee. It verifies that SMB messages have not been altered in transit.

- **Signing only (SMB 2 compatible)** is the default. It permits signed, unencrypted SMB 2 connections for trusted home and small-organization networks. File contents, names, and metadata are visible to network observers in this mode.
- **Signing and encryption (SMB 3+)** requires encrypted SMB traffic. Choose it for shared or untrusted networks that need confidentiality. This blocks SMB 2-only servers because SMB encryption requires SMB 3 or later.

## Connection Behavior

Set the SMB connection timeout to limit how long Sambee waits to establish a transport connection.

## Domain-Based DFS

For domain-based DFS namespaces, configure the primary and secondary domain controllers in the **Domain-based DFS** fields above. Sambee tries them in configured order for the process-wide DFS referral cache and uses the first one that initializes successfully. This is startup/setup fallback, not continuous health-based failover.

Configure a namespace connection using the existing connection fields:

- `\\domain.example\\Namespace\\Share` → host `domain.example`, share `Namespace`, path prefix `/Share`.
- `\\domain.example\\Share` → host `domain.example`, share `Share`, path prefix `/`.

For DFS connections, leave **Live directory updates** disabled unless the deployment has been specifically validated with that namespace. Browsing and manual refresh remain available.


Set the SMB read chunk size to control how much file data Sambee reads per streaming operation. The setting is stored as an administrator setting and is not available in `config.toml`.


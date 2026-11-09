import type { CompanionDriveDescriptor, CompanionSessionSnapshot } from "./storageContracts";

const KEY_DATABASE = "sambee-companion-auth";
const KEY_STORE = "browser-keys";
const KEY_ID = "current-origin";
const KEY_ALGORITHM: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_ALGORITHM: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

type Listener = () => void;
type StoredKeyPair = { id: string; privateKey: CryptoKey; publicKey: CryptoKey };

export function canSignCompanionRequests(): boolean {
  return globalThis.isSecureContext !== false && typeof crypto.subtle !== "undefined";
}

function haveSameDrives(left: readonly CompanionDriveDescriptor[], right: readonly CompanionDriveDescriptor[]): boolean {
  return (
    left.length === right.length &&
    left.every(
      (drive, index) => drive.driveId === right[index]?.driveId && drive.name === right[index]?.name && drive.path === right[index]?.path
    )
  );
}

function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_DATABASE, 1);
    request.onerror = () => reject(request.error ?? new Error("Unable to open companion key storage"));
    request.onupgradeneeded = () => request.result.createObjectStore(KEY_STORE, { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
  });
}

async function readKeyPair(): Promise<StoredKeyPair | null> {
  if (!canSignCompanionRequests() || typeof indexedDB === "undefined") return null;
  const database = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const request = database.transaction(KEY_STORE, "readonly").objectStore(KEY_STORE).get(KEY_ID);
    request.onerror = () => reject(request.error ?? new Error("Unable to read companion key"));
    request.onsuccess = () => resolve((request.result as StoredKeyPair | undefined) ?? null);
  });
}

async function writeKeyPair(keyPair: Omit<StoredKeyPair, "id">): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  const database = await openKeyDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = database
      .transaction(KEY_STORE, "readwrite")
      .objectStore(KEY_STORE)
      .put({ id: KEY_ID, ...keyPair });
    request.onerror = () => reject(request.error ?? new Error("Unable to persist companion key"));
    request.onsuccess = () => resolve();
  });
}

async function deleteKeyPair(): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  const database = await openKeyDatabase();
  await new Promise<void>((resolve, reject) => {
    const request = database.transaction(KEY_STORE, "readwrite").objectStore(KEY_STORE).delete(KEY_ID);
    request.onerror = () => reject(request.error ?? new Error("Unable to remove companion key"));
    request.onsuccess = () => resolve();
  });
}

function toBase64(bytes: ArrayBuffer): string {
  let value = "";
  for (const byte of new Uint8Array(bytes)) value += String.fromCharCode(byte);
  return btoa(value);
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (character) => character.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (character) => character.codePointAt(0) ?? 0);
  for (const [index, leftPoint] of leftPoints.entries()) {
    const rightPoint = rightPoints[index];
    if (rightPoint === undefined) break;
    if (leftPoint !== rightPoint) return leftPoint - rightPoint;
  }
  return leftPoints.length - rightPoints.length;
}

export class CompanionSession {
  private revision = 0;
  private snapshot: CompanionSessionSnapshot = { status: "unpaired", revision: 0, drives: [], error: null };
  private readonly listeners = new Set<Listener>();
  private keyPair: StoredKeyPair | null = null;

  async load(): Promise<void> {
    try {
      this.keyPair = await readKeyPair();
    } catch {
      this.keyPair = null;
    }
  }
  getSnapshot(): CompanionSessionSnapshot {
    return this.snapshot;
  }
  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  setState(
    status: CompanionSessionSnapshot["status"],
    drives: readonly CompanionDriveDescriptor[] = [],
    error: CompanionSessionSnapshot["error"] = null
  ): void {
    if (this.snapshot.status === status && this.snapshot.error === error && haveSameDrives(this.snapshot.drives, drives)) return;
    this.revision += 1;
    this.snapshot = { status, drives, error, revision: this.revision };
    for (const listener of this.listeners) listener();
  }
  hasSecret(): boolean {
    return this.keyPair !== null;
  }
  async ensureKeyPair(): Promise<StoredKeyPair> {
    if (!canSignCompanionRequests()) throw new Error("Secure companion key storage is unavailable");
    this.keyPair = this.keyPair ?? (await readKeyPair());
    if (this.keyPair) return this.keyPair;
    const generated = (await crypto.subtle.generateKey(KEY_ALGORITHM, false, ["sign", "verify"])) as CryptoKeyPair;
    const keyPair = { id: KEY_ID, privateKey: generated.privateKey, publicKey: generated.publicKey };
    try {
      await writeKeyPair(keyPair);
    } catch {
      // Secure persistence is best effort. Keep the non-exportable key in memory
      // for this browser session; never downgrade to readable storage.
    }
    this.keyPair = keyPair;
    return keyPair;
  }
  async getPublicKey(): Promise<string> {
    return toBase64(await crypto.subtle.exportKey("raw", (await this.ensureKeyPair()).publicKey));
  }
  async preparePairing(): Promise<string> {
    return this.getPublicKey();
  }
  async storePairing(): Promise<void> {
    await this.ensureKeyPair();
    this.setState("paired", this.snapshot.drives);
  }
  clearPairing(): void {
    this.keyPair = null;
    void deleteKeyPair().catch(() => undefined);
    this.setState("unpaired");
  }
  async getSigningHeaders(method: string, url: string, body = ""): Promise<Record<string, string>> {
    const keyPair = await this.ensureKeyPair();
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonceBytes = new Uint8Array(16);
    crypto.getRandomValues(nonceBytes);
    const nonce = toBase64(nonceBytes.buffer);
    const target = new URL(url, `${window.location.origin}/`);
    const parameters: [string, string][] = [...target.searchParams.entries()]
      .filter(([key]) => !["hmac", "ts", "origin", "sig", "nonce", "key", "body_sha256"].includes(key))
      .map(([key, value]) => [key, value] as [string, string])
      .sort((left, right) => compareCodePoints(left[0], right[0]) || compareCodePoints(left[1], right[1]));
    const query = new URLSearchParams(parameters).toString();
    const path = target.pathname + (query ? `?${query}` : "");
    const bodyHash = toBase64(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)));
    const payload = `${window.location.origin}\n${timestamp}\n${nonce}\n${method.toUpperCase()}\n${path}\n${bodyHash}`;
    const signature = toBase64(await crypto.subtle.sign(SIGN_ALGORITHM, keyPair.privateKey, new TextEncoder().encode(payload)));
    const publicKey = await this.getPublicKey();
    const headers: Record<string, string> = {
      "X-Companion-Key": publicKey,
      "X-Companion-Signature": signature,
      "X-Companion-Timestamp": timestamp,
      "X-Companion-Nonce": nonce,
      "X-Companion-Body-SHA256": bodyHash,
    };
    return headers;
  }
  async getSignedQuery(method: string, url: string): Promise<string> {
    const headers = await this.getSigningHeaders(method, url);
    const signature = headers["X-Companion-Signature"] ?? "";
    const timestamp = headers["X-Companion-Timestamp"] ?? "";
    const nonce = headers["X-Companion-Nonce"] ?? "";
    const publicKey = headers["X-Companion-Key"] ?? "";
    const bodyHash = headers["X-Companion-Body-SHA256"] ?? "";
    return `sig=${encodeURIComponent(signature)}&ts=${timestamp}&nonce=${encodeURIComponent(nonce)}&key=${encodeURIComponent(publicKey)}&body_sha256=${encodeURIComponent(bodyHash)}&origin=${encodeURIComponent(window.location.origin)}`;
  }
}

export const companionSession = new CompanionSession();

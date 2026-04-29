import type { OpenClawConfig } from "../../config/types.openclaw.js";
import type { ProviderExternalAuthProfile } from "../../plugins/provider-external-auth.types.js";
import { resolveExternalAuthProfilesWithPlugins } from "../../plugins/provider-runtime.js";
import * as externalCliSync from "./external-cli-sync.js";
import {
  overlayRuntimeExternalOAuthProfiles,
  shouldPersistRuntimeExternalOAuthProfile,
  type RuntimeExternalOAuthProfile,
} from "./oauth-shared.js";
import type { AuthProfileStore, OAuthCredential } from "./types.js";

type ExternalAuthProfileMap = Map<string, ProviderExternalAuthProfile>;
type ResolveExternalAuthProfiles = typeof resolveExternalAuthProfilesWithPlugins;

export type ExternalAuthProfileOverlayOptions = {
  agentDir?: string;
  allowKeychainPrompt?: boolean;
  config?: OpenClawConfig;
  eligibleProfileIds?: Iterable<string>;
  eligibleProviderIds?: Iterable<string>;
  env?: NodeJS.ProcessEnv;
};

let resolveExternalAuthProfilesForRuntime: ResolveExternalAuthProfiles | undefined;

export const __testing = {
  resetResolveExternalAuthProfilesForTest(): void {
    resolveExternalAuthProfilesForRuntime = undefined;
  },
  setResolveExternalAuthProfilesForTest(resolver: ResolveExternalAuthProfiles): void {
    resolveExternalAuthProfilesForRuntime = resolver;
  },
};

function normalizeExternalAuthProfile(
  profile: ProviderExternalAuthProfile,
): ProviderExternalAuthProfile | null {
  if (!profile?.profileId || !profile.credential) {
    return null;
  }
  return {
    ...profile,
    persistence: profile.persistence ?? "runtime-only",
  };
}

function resolveExternalAuthProfileMap(params: {
  store: AuthProfileStore;
  options?: ExternalAuthProfileOverlayOptions;
}): ExternalAuthProfileMap {
  const env = params.options?.env ?? process.env;
  const resolveProfiles =
    resolveExternalAuthProfilesForRuntime ?? resolveExternalAuthProfilesWithPlugins;
  const profiles = resolveProfiles({
    env,
    config: params.options?.config,
    context: {
      config: params.options?.config,
      agentDir: params.options?.agentDir,
      workspaceDir: undefined,
      env,
      store: params.store,
    },
  });

  const resolved: ExternalAuthProfileMap = new Map();
  const cliProfiles =
    externalCliSync.resolveExternalCliAuthProfiles?.(params.store, {
      allowKeychainPrompt: params.options?.allowKeychainPrompt,
      eligibleProfileIds: params.options?.eligibleProfileIds,
      eligibleProviderIds: params.options?.eligibleProviderIds,
    }) ?? [];
  for (const profile of cliProfiles) {
    resolved.set(profile.profileId, {
      profileId: profile.profileId,
      credential: profile.credential,
      persistence: "runtime-only",
    });
  }
  for (const rawProfile of profiles) {
    const profile = normalizeExternalAuthProfile(rawProfile);
    if (!profile) {
      continue;
    }
    resolved.set(profile.profileId, profile);
  }
  return resolved;
}

function listRuntimeExternalAuthProfiles(params: {
  store: AuthProfileStore;
  options?: ExternalAuthProfileOverlayOptions;
}): RuntimeExternalOAuthProfile[] {
  return Array.from(
    resolveExternalAuthProfileMap({
      store: params.store,
      options: params.options,
    }).values(),
  );
}

export function overlayExternalAuthProfiles(
  store: AuthProfileStore,
  params?: ExternalAuthProfileOverlayOptions,
): AuthProfileStore {
  const profiles = listRuntimeExternalAuthProfiles({
    store,
    options: params,
  });
  return overlayRuntimeExternalOAuthProfiles(store, profiles);
}

export function shouldPersistExternalAuthProfile(params: {
  store: AuthProfileStore;
  profileId: string;
  credential: OAuthCredential;
  agentDir?: string;
  allowKeychainPrompt?: boolean;
  config?: OpenClawConfig;
  eligibleProfileIds?: Iterable<string>;
  eligibleProviderIds?: Iterable<string>;
  env?: NodeJS.ProcessEnv;
}): boolean {
  const profiles = listRuntimeExternalAuthProfiles({
    store: params.store,
    options: {
      agentDir: params.agentDir,
      allowKeychainPrompt: params.allowKeychainPrompt,
      config: params.config,
      eligibleProfileIds: params.eligibleProfileIds,
      eligibleProviderIds: params.eligibleProviderIds,
      env: params.env,
    },
  });
  return shouldPersistRuntimeExternalOAuthProfile({
    profileId: params.profileId,
    credential: params.credential,
    profiles,
  });
}

// Compat aliases while file/function naming catches up.
export const overlayExternalOAuthProfiles = overlayExternalAuthProfiles;
export const shouldPersistExternalOAuthProfile = shouldPersistExternalAuthProfile;

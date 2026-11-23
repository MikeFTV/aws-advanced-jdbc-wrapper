/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package software.amazon.jdbc.util;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Derives a value from a credential, such as a password, that a cache or pool key can include in
 * place of the credential itself.
 *
 * <p>The value is an HMAC-SHA256 of the credential under a random key generated once per JVM. Equal
 * credentials give equal values within one JVM, but the value cannot be reversed or compared with a
 * precomputed table, and it differs between JVM runs.
 */
public final class CredentialFingerprint {

  private static final String ALGORITHM = "HmacSHA256";
  private static final byte[] KEY = newKey();

  private CredentialFingerprint() {
  }

  /**
   * Returns the fingerprint of the given credential.
   *
   * @param credential the credential, or {@code null}
   * @return the Base64-encoded fingerprint, or {@code null} if the credential is {@code null}. An
   *     empty credential has a fingerprint, so it is distinguished from an absent one.
   */
  public static @Nullable String of(final @Nullable String credential) {
    if (credential == null) {
      return null;
    }
    try {
      final Mac mac = Mac.getInstance(ALGORITHM);
      mac.init(new SecretKeySpec(KEY, ALGORITHM));
      return Base64.getEncoder().encodeToString(mac.doFinal(credential.getBytes(StandardCharsets.UTF_8)));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException(Messages.get("CredentialFingerprint.hmacNotAvailable"), e);
    }
  }

  private static byte[] newKey() {
    final byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }
}

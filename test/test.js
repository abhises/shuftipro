import ShuftiProKyc from "../service/ShuftiProKyc.js";
import { signatureFor } from "../helper/tinyHelper";

async function test() {
  // Configure the class
  ShuftiProKyc.configure({
    CLIENT_ID: "client_123",
    SECRET_KEY: "secret_abc",
    API_URL: "https://mock.shufti/api",
    CALLBACK_URL: "https://your.app/kyc/webhook",
    REDIRECT_URL: "https://your.app/kyc/status",
    TABLE: "kyc_shufti",
  });

  const userId = "u1";
  const userEmail = "user@example.com";

  // 1) Happy path: create a new session
  CURRENT_FETCH_MODE = FetchMode.HAPPY;
  const { reference, verificationUrl } =
    await ShuftiProKyc.createVerificationSession({
      userId,
      userEmail,
      appLocale: "en-AU",
      userCountry: "AU",
      verificationMode: "any",
      documentConfig: { name: "John Doe", dob: "1990-01-01" },
    });
  console.log("NEW SESSION:", { reference, verificationUrl });

  // 2) Try to create again: should reuse ACTIVE (request.pending)
  const reuseActive = await ShuftiProKyc.createVerificationSession({
    userId,
    userEmail,
    appLocale: "en-AU",
    userCountry: "AU",
  });
  console.log("REUSE ACTIVE:", reuseActive);

  // 3) Webhook accepted
  {
    const acceptedPayload = JSON.stringify({
      reference,
      event: KYC_EVENT.VERIFICATION_ACCEPTED,
    });
    const sig = signatureFor(acceptedPayload, "secret_abc");
    const webhookRes = await ShuftiProKyc.handleWebhook({
      rawBodyString: acceptedPayload,
      signatureHeader: sig,
    });
    console.log("WEBHOOK ACCEPTED:", webhookRes);
  }

  // 4) After accepted, creating again should return alreadyValidated
  const reuseValidated = await ShuftiProKyc.createVerificationSession({
    userId,
    userEmail,
  });
  console.log("REUSE VALIDATED:", reuseValidated);

  // 5) Non-200 response still logs error, returns reference (since we store attempt anyway)
  CURRENT_FETCH_MODE = FetchMode.NON_200;
  const non200 = await ShuftiProKyc.createVerificationSession({
    userId,
    userEmail,
  });
  console.log("NON-200 CREATE:", non200);

  // 6) Invalid JSON response → throws
  CURRENT_FETCH_MODE = FetchMode.INVALID_JSON;
  try {
    await ShuftiProKyc.createVerificationSession({ userId, userEmail });
  } catch (e) {
    console.log("INVALID JSON CREATE (caught):", e.message);
  }

  // 7) Bad signature response → throws
  CURRENT_FETCH_MODE = FetchMode.BAD_SIGNATURE;
  try {
    await ShuftiProKyc.createVerificationSession({ userId, userEmail });
  } catch (e) {
    console.log("BAD SIGNATURE CREATE (caught):", e.message);
  }

  // 8) Network error → throws
  CURRENT_FETCH_MODE = FetchMode.NETWORK_ERROR;
  try {
    await ShuftiProKyc.createVerificationSession({ userId, userEmail });
  } catch (e) {
    console.log("NETWORK ERROR CREATE (caught):", e.message);
  }

  // Reset to HAPPY for webhook tests
  CURRENT_FETCH_MODE = FetchMode.HAPPY;

  // 9) Webhook invalid signature
  {
    const body = JSON.stringify({
      reference,
      event: KYC_EVENT.VERIFICATION_DECLINED,
    });
    const badSig = "WRONG";
    const wb = await ShuftiProKyc.handleWebhook({
      rawBodyString: body,
      signatureHeader: badSig,
    });
    console.log("WEBHOOK BAD SIG:", wb);
  }

  // 10) Webhook invalid JSON
  {
    const wb = await ShuftiProKyc.handleWebhook({
      rawBodyString: "{ nope",
      signatureHeader: "whatever",
    });
    console.log("WEBHOOK BAD JSON:", wb);
  }

  // 11) Manual status update for NON-EXISTENT ref → false
  const statusFalse = await ShuftiProKyc.updateRecordStatus(
    "ref-does-not-exist",
    KYC_EVENT.VERIFICATION_ACCEPTED
  );
  console.log("UPDATE STATUS (missing meta):", statusFalse);

  // 12) Rate limit: spam > PER_MINUTE_LIMIT
  for (let i = 0; i < CONFIG.PER_MINUTE_LIMIT + 5; i++) {
    try {
      await ShuftiProKyc.createVerificationSession({
        userId: "flood",
        userEmail: "flood@example.com",
      });
    } catch {
      /* ignore failures here */
    }
  }
  console.log("RATE LIMIT test completed (check logs & DB rows)");

  // Final: pull a full record by reference
  const fullRecord = await ShuftiProKyc.getRecordByReference(reference);
  console.log("FULL RECORD (by reference):", !!fullRecord, {
    keys: Object.keys(fullRecord || {}),
  });

  // isUserValidated checks
  const isVal = await ShuftiProKyc.isUserValidated(userId);
  console.log("isUserValidated:", isVal);
}

test();

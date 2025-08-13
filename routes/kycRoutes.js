import express from "express";
import ShuftiProKyc from "../service/ShuftiProKyc.js";
import ScyllaDb from "../utils/ScyllaDb.js";
import { signatureFor } from "../helper/tinyHelper.js";
import { KYC_EVENT } from "../constants/constants.js";
const router = express.Router();

// Example: Create KYC session
router.post("/create", async (req, res) => {
  try {
    const { userId, userEmail, appLocale, userCountry, documentConfig } =
      req.body;
    const result = await ShuftiProKyc.createVerificationSession({
      userId,
      userEmail,
      appLocale,
      userCountry,
      documentConfig,
    });
    res.status(201).json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Example: Webhook endpoint
router.post("/webhook", async (req, res) => {
  try {
    await ScyllaDb.loadTableConfigs("./tables.json");
    const { reference } = req.body;
    const rawBodyString = JSON.stringify({
      reference,
      event: KYC_EVENT.VERIFICATION_ACCEPTED,
    });
    const signatureHeader = signatureFor(rawBodyString, "secret_abc");
    const result = await ShuftiProKyc.handleWebhook({
      rawBodyString,
      signatureHeader,
    });
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Example: Get KYC record
router.get("/record/:reference", async (req, res) => {
  try {
    const { reference } = req.params;
    const record = await ShuftiProKyc.getRecordByReference(reference);
    res.json(record);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

router.get("/checkingValidate/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const isValidated = await ShuftiProKyc.isUserValidated(userId);
    res.json({ userId, isValidated });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /update-status
 * Updates the verification status of a record
 * Body: { reference: string, newStatus: string }
 */
router.post("/update-status", async (req, res) => {
  try {
    await ScyllaDb.loadTableConfigs("./tables.json");

    const { reference, newStatus } = req.body;
    if (!reference || !newStatus) {
      return res
        .status(400)
        .json({ error: "reference and newStatus are required" });
    }

    const success = await ShuftiProKyc.updateRecordStatus(reference, newStatus);
    if (!success) {
      return res
        .status(404)
        .json({ error: "Record not found or update failed" });
    }

    res.json({ reference, newStatus, updated: success });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

export default router;

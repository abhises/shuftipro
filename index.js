import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import kycRoutes from "./routes/kycRoutes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Routes
app.use("/kyc", kycRoutes);

app.get("/", (req, res) => {
  res.send("KYC API running!");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

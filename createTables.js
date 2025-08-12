import fs from "fs";
import path from "path";
import ScyllaDb from "./utils/ScyllaDb.js"; // your existing wrapper

async function run() {
  const filePath = path.resolve("./tables.json");
  const tables = JSON.parse(fs.readFileSync(filePath, "utf8"));

  for (const [tableName, schema] of Object.entries(tables)) {
    try {
      console.log(`Creating table: ${tableName}`);
      const resp = await ScyllaDb.createTable(schema);
      console.log(`✅ Created: ${tableName}`, resp);
    } catch (err) {
      console.error(`❌ Failed to create ${tableName}:`, err.message);
    }
  }
}

run().catch(console.error);
